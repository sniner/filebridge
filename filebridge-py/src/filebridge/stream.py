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

from .exceptions import FileBridgeError, IsDirectoryError

CHUNK_SIZE = 64 * 1024
"""Default chunk size (64 KiB) for stream framing and buffered writes."""


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


def _derive_json_key_nonce(token: str, iv_hex: str) -> tuple[bytes, bytes]:
    """Derive key and nonce for JSON response encryption/decryption."""
    if not iv_hex:
        raise ValueError("iv_hex must not be empty")
    prk = _hkdf_extract(iv_hex.encode(), token.encode())
    key = _hkdf_expand(prk, b"filebridge-json-key", 32)
    nonce = _hkdf_expand(prk, b"filebridge-json-nonce", 12)
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


def _derive_block_nonce(token: str, iv_hex: str) -> tuple[ChaCha20Poly1305, bytes]:
    """Shared key+nonce derivation for single-block JSON encryption."""
    key, nonce = _derive_json_key_nonce(token, iv_hex)
    cipher = ChaCha20Poly1305(key)
    return cipher, nonce


def encrypt_json_response(token: str, iv_hex: str, json_bytes: bytes) -> str:
    """Compress, encrypt and base64-encode JSON bytes for a token-protected response."""
    compressed = zstandard.ZstdCompressor(level=3).compress(json_bytes)
    cipher, nonce = _derive_block_nonce(token, iv_hex)
    ciphertext = cipher.encrypt(nonce, compressed, None)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_json_response(token: str, iv_hex: str, encoded: str) -> bytes:
    """Base64-decode, decrypt and decompress an encrypted JSON response."""
    data = base64.b64decode(encoded)
    cipher, nonce = _derive_block_nonce(token, iv_hex)
    try:
        compressed = cipher.decrypt(nonce, data, None)
    except InvalidTag as e:
        raise StreamError(f"JSON response decryption failed: {e}")
    return zstandard.ZstdDecompressor().decompress(compressed)


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
) -> str:
    """Build an encrypted request envelope containing path and params."""
    envelope: dict[str, Any] = {"path": path.lstrip("/")}
    if offset is not None:
        envelope["offset"] = offset
    if length is not None:
        envelope["length"] = length
    if extensive:
        envelope["extensive"] = True
    json_bytes = json.dumps(envelope, separators=(",", ":")).encode()
    return encrypt_json_response(token, sig, json_bytes)


def parse_json_response(token: str | None, signature: str | None, body: bytes) -> dict:
    """Parse a JSON response body, decrypting it first when token+signature are present."""
    parsed = json.loads(body)
    if token and signature:
        message = parsed.get("message")
        if message is None:
            raise FileBridgeError("Missing 'message' field in encrypted response")
        try:
            json_bytes = decrypt_json_response(token, signature, message)
        except StreamError as e:
            raise FileBridgeError(f"JSON response decryption failed: {e}")
        return json.loads(json_bytes)
    return parsed


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
    """Decrypt and verify a complete stream response body."""
    decoder = StreamDecoder()
    aead = StreamAead(token, signature)
    decoder.push(content)

    result_bytes = bytearray()
    while True:
        frame = decoder.next_frame()
        if not frame:
            break
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


def decode_read_response(
    token: str | None,
    content_type: str,
    content: bytes,
    sig: str | None,
    path: str,
) -> bytes:
    """Evaluate Content-Type and return decoded payload bytes.

    Raises IsDirectoryError for directory JSON responses, FileBridgeError
    for missing signature in stream mode.
    """
    if "application/json" in content_type:
        data = parse_json_response(token, sig if token else None, content)
        if "items" in data:
            raise IsDirectoryError(f"{path} is a directory")

    if "application/vnd.filebridge.stream" in content_type:
        if not sig or not token:
            raise FileBridgeError("Missing signature for stream verification")
        return decode_verified_stream_content(token, sig, content)

    return content
