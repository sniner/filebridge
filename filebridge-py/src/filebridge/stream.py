"""Streaming protocol and encryption primitives for the Filebridge wire format."""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import struct
from typing import NamedTuple

import zstandard
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


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
