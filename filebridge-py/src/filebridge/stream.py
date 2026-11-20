"""Streaming protocol and encryption primitives for the Filebridge wire format."""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import struct
from typing import Any, NamedTuple

import zstandard
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from typing import Literal

from .exceptions import FileBridgeError

CHUNK_SIZE = 64 * 1024
"""Default chunk size (64 KiB) for stream framing and buffered writes."""

JsonDirection = Literal["request", "response"]
"""Direction of an encrypted JSON payload.

Request envelopes (client → server) and JSON responses (server → client) are
encrypted under the same (token, signature) pair. Deriving a separate key and
nonce per direction guarantees each derived (key, nonce) encrypts at most one
message, ruling out nonce reuse across the two directions.
"""


class StreamError(Exception):
    """Raised on stream protocol or cryptographic errors."""


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract step: PRK = HMAC-SHA256(salt, ikm)."""
    return _hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand step using cryptography library."""
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def _derive_stream_key_nonce(token: str, iv_hex: str) -> tuple[bytes, bytes]:
    """Derive key and nonce base for stream AEAD encryption/decryption."""
    if not iv_hex:
        raise ValueError("iv_hex must not be empty")
    prk = _hkdf_extract(iv_hex.encode(), token.encode())
    key = _hkdf_expand(prk, b"filebridge-stream-key", 32)
    nonce_base = _hkdf_expand(prk, b"filebridge-stream-nonce", 12)
    return key, nonce_base


def _derive_json_key_nonce(
    token: str,
    iv_hex: str,
    direction: JsonDirection,
) -> tuple[bytes, bytes]:
    """Derive key and nonce for encrypted JSON payloads, separated by direction."""
    if not iv_hex:
        raise ValueError("iv_hex must not be empty")
    prk = _hkdf_extract(iv_hex.encode(), token.encode())
    key = _hkdf_expand(prk, f"filebridge-json-{direction}-key".encode(), 32)
    nonce = _hkdf_expand(prk, f"filebridge-json-{direction}-nonce".encode(), 12)
    return key, nonce


class StreamAead:
    """ChaCha20-Poly1305 AEAD for encrypting/decrypting stream chunks."""

    def __init__(self, token: str, iv_hex: str):
        key, nonce_base = _derive_stream_key_nonce(token, iv_hex)
        self.cipher = ChaCha20Poly1305(key)
        self.nonce_base = bytearray(nonce_base)
        self.counter = 0

    def _current_nonce(self) -> bytes:
        nonce_bytes = bytearray(self.nonce_base)
        counter_bytes = struct.pack(">Q", self.counter)
        for i in range(8):
            nonce_bytes[4 + i] ^= counter_bytes[i]
        return bytes(nonce_bytes)

    def encrypt(self, data: bytes) -> bytes:
        nonce = self._current_nonce()
        ciphertext = self.cipher.encrypt(nonce, data, None)
        self.counter += 1
        return ciphertext

    def decrypt(self, data: bytes) -> bytes:
        nonce = self._current_nonce()
        try:
            plaintext = self.cipher.decrypt(nonce, data, None)
            self.counter += 1
            return plaintext
        except InvalidTag as e:
            raise StreamError(f"Decryption failed: {e}")

    def finalize(self) -> str:
        final_block = self.encrypt(b"")
        return final_block.hex()

    def verify_stop(self, hex_sig: str):
        try:
            final_block = bytes.fromhex(hex_sig)
            self.decrypt(final_block)
        except (ValueError, StreamError) as e:
            raise StreamError(f"Invalid stop signature: {e}")


def encode_meta(payload: bytes) -> bytes:
    frame = bytearray(b"META")
    frame.extend(struct.pack(">I", len(payload)))
    frame.extend(payload)
    return bytes(frame)


def encode_data(payload: bytes) -> bytes:
    frame = bytearray(b"DATA")
    frame.extend(struct.pack(">I", len(payload)))
    frame.extend(payload)
    return bytes(frame)


def encode_stop(signature: str | None = None) -> bytes:
    frame = bytearray(b"STOP")
    if signature:
        sig_bytes = signature.encode()
        frame.extend(struct.pack(">I", len(sig_bytes)))
        frame.extend(sig_bytes)
    else:
        frame.extend(struct.pack(">I", 0))
    return bytes(frame)


def _derive_block_nonce(
    token: str,
    iv_hex: str,
    direction: JsonDirection,
) -> tuple[ChaCha20Poly1305, bytes]:
    """Shared key+nonce derivation for single-block JSON encryption."""
    key, nonce = _derive_json_key_nonce(token, iv_hex, direction)
    cipher = ChaCha20Poly1305(key)
    return cipher, nonce


PAD_BLOCK = 256
"""Encrypted JSON payloads are padded to a multiple of this many bytes.

Without padding the length of a request shows the length of its path, and the
length of a response shows which of the short replies it is: an error, an
acknowledgement or the metadata of a file.
"""


def _pad(data: bytes) -> bytes:
    """Pad to a multiple of ``PAD_BLOCK`` with ``0x80`` and zero bytes (ISO/IEC 7816-4)."""
    padded = data + b"\x80"
    return padded + bytes(-len(padded) % PAD_BLOCK)


def _unpad(data: bytes) -> bytes:
    stripped = data.rstrip(b"\x00")
    if not stripped.endswith(b"\x80"):
        raise StreamError("Invalid padding")
    return stripped[:-1]


def encrypt_json(
    token: str,
    iv_hex: str,
    json_bytes: bytes,
    direction: JsonDirection,
) -> str:
    """Compress, pad, encrypt and base64-encode JSON bytes for the given direction."""
    compressed = zstandard.ZstdCompressor(level=3).compress(json_bytes)
    cipher, nonce = _derive_block_nonce(token, iv_hex, direction)
    ciphertext = cipher.encrypt(nonce, _pad(compressed), None)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_json(
    token: str,
    iv_hex: str,
    encoded: str,
    direction: JsonDirection,
) -> bytes:
    """Base64-decode, decrypt, unpad and decompress an encrypted JSON payload."""
    data = base64.b64decode(encoded)
    cipher, nonce = _derive_block_nonce(token, iv_hex, direction)
    try:
        padded = cipher.decrypt(nonce, data, None)
    except InvalidTag as e:
        raise StreamError(f"JSON decryption failed: {e}")
    return zstandard.ZstdDecompressor().decompress(_unpad(padded))


class StreamFrame(NamedTuple):
    """A decoded stream frame."""

    tag: str
    signature: str | None
    payload: bytes


class StreamDecoder:
    """Incremental decoder for the filebridge binary stream protocol.

    Feed data with ``push()``, then call ``next_frame()`` repeatedly
    to extract complete frames.
    """

    def __init__(self):
        self.buffer = bytearray()
        self.offset = 0

    def push(self, chunk: bytes):
        """Append raw bytes to the internal buffer."""
        self.buffer.extend(chunk)

    def next_frame(self) -> StreamFrame | None:
        """Return the next complete frame, or ``None`` if more data is needed."""
        rem_len = len(self.buffer) - self.offset
        if rem_len < 8:
            return None

        tag = bytes(self.buffer[self.offset : self.offset + 4]).decode("ascii")
        length = struct.unpack(">I", self.buffer[self.offset + 4 : self.offset + 8])[0]

        if rem_len < 8 + length:
            return None

        payload = bytes(self.buffer[self.offset + 8 : self.offset + 8 + length])

        # Advance buffer offset
        self.offset += 8 + length

        # Periodically compact buffer to release memory if we've processed a lot
        if self.offset > 1024 * 1024:
            del self.buffer[: self.offset]
            self.offset = 0

        sig_str = None
        if tag == "STOP":
            if length > 0:
                sig_str = payload.decode("ascii")

        return StreamFrame(tag=tag, signature=sig_str, payload=payload)


# ---------------------------------------------------------------------------
# Higher-level operations that combine crypto primitives with the wire format
# ---------------------------------------------------------------------------


def build_encrypted_envelope(
    token: str,
    sig: str,
    path: str,
    offset: int | None = None,
    length: int | None = None,
    extensive: bool = False,
    target: str | None = None,
    content: bool = False,
) -> str:
    """Build an encrypted request envelope containing path and params.

    With *content*, a GET is answered with the content of the file instead of
    its metadata.
    """
    envelope: dict[str, Any] = {"path": path.lstrip("/")}
    if target is not None:
        envelope["target"] = target.lstrip("/")
    if offset is not None:
        envelope["offset"] = offset
    if length is not None:
        envelope["length"] = length
    if extensive:
        envelope["extensive"] = True
    if content:
        envelope["content"] = True
    json_bytes = json.dumps(envelope, separators=(",", ":")).encode()
    return encrypt_json(token, sig, json_bytes, "request")


class Reply(NamedTuple):
    """Plaintext of the encrypted response of a location with a token.

    Every response to an authenticated request is either an encrypted file
    stream or one of these. The HTTP status line says ``200`` in both cases;
    the status of the operation is ``status``, so that it is covered by the
    authentication tag and hidden from an observer.
    """

    status: int
    """HTTP status code of the operation."""
    error: str | None = None
    """The server's message, when ``status`` is an error."""
    body: Any = None
    """The JSON result, for an operation that has one."""


def seal_reply(token: str, iv_hex: str, reply: Reply) -> bytes:
    """Encrypt *reply* and return the HTTP response body that carries it."""
    plain: dict[str, Any] = {"status": reply.status}
    if reply.error is not None:
        plain["error"] = reply.error
    if reply.body is not None:
        plain["body"] = reply.body
    message = encrypt_json(token, iv_hex, json.dumps(plain).encode(), "response")
    return json.dumps({"message": message}).encode()


def open_reply(token: str, iv_hex: str, body: bytes) -> Reply:
    """Decrypt and verify an HTTP response body made by ``seal_reply``.

    Raises ``StreamError`` for anything else, such as a plain-text error or a
    response that was altered in transit.
    """
    try:
        message = json.loads(body)["message"]
        plain = json.loads(decrypt_json(token, iv_hex, message, "response"))
        status = plain["status"]
        error = plain.get("error")
    except StreamError:
        raise
    except Exception as e:
        raise StreamError(f"Malformed encrypted response: {e}") from None
    if type(status) is not int or not (error is None or isinstance(error, str)):
        raise StreamError("Malformed encrypted response: wrong field type")
    return Reply(status=status, error=error, body=plain.get("body"))


def build_encrypted_write_body(
    token: str,
    sig: str,
    data: bytes,
    path: str | None = None,
    offset: int | None = None,
) -> bytes:
    """Pack `data` into signed stream frames (ChaCha20Poly1305).

    When *path* is given, a META frame with the encrypted envelope is prepended
    (token-mode: path not in URL).
    """
    buf = bytearray()
    if path is not None:
        envelope = build_encrypted_envelope(token, sig, path, offset)
        buf.extend(encode_meta(envelope.encode()))
    aead = StreamAead(token, sig)
    for i in range(0, len(data), CHUNK_SIZE):
        buf.extend(encode_data(aead.encrypt(data[i : i + CHUNK_SIZE])))
    buf.extend(encode_stop(aead.finalize()))
    return bytes(buf)


def decode_verified_stream_content(token: str, signature: str, content: bytes) -> bytes:
    """Decrypt and verify a complete stream response body.

    Every DATA frame is authenticated on its own, so a body cut off after any
    frame still decrypts. Only the STOP frame shows that the stream is whole.
    """
    decoder = StreamDecoder()
    aead = StreamAead(token, signature)
    decoder.push(content)

    result_bytes = bytearray()
    while True:
        frame = decoder.next_frame()
        if not frame:
            raise FileBridgeError("Unexpected EOF before STOP frame")
        tag, sig_str, payload = frame
        if tag == "DATA":
            try:
                result_bytes.extend(aead.decrypt(payload))
            except StreamError:
                raise FileBridgeError("Chunk Authenticated Decryption failed")
        elif tag == "STOP":
            if not sig_str:
                raise FileBridgeError("Stop frame missing signature")
            try:
                aead.verify_stop(sig_str)
            except StreamError:
                raise FileBridgeError("Stop signature mismatch")
            break
    return bytes(result_bytes)
