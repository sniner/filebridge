from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any
from urllib.parse import urlparse

from .exceptions import (
    AuthenticationError,
    FileBridgeError,
    FileBridgePermissionError,
    IsDirectoryError,
    NotFoundError,
)


def calculate_signature(
    token: str | None, method: str, url: str, timestamp: str, nonce: str
) -> str:
    if not token:
        return ""

    parsed = urlparse(url)
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query

    mac = hmac.new(token.encode(), digestmod=hashlib.sha256)
    mac.update(timestamp.encode())
    mac.update(nonce.encode())
    mac.update(method.upper().encode())
    mac.update(path.encode())

    return mac.hexdigest()


def get_api_path(dir_id: str, path: str | None, *, use_encrypted_body: bool = False) -> str:
    """Build the API path, stripping leading slashes from the requested path.

    When *use_encrypted_body* is True the path is omitted from the URL
    (it will be sent in an encrypted body instead).
    """
    if use_encrypted_body:
        return f"api/v1/fs/{dir_id}"
    if path:
        clean_path = path.lstrip("/")
        if clean_path:
            return f"api/v1/fs/{dir_id}/{clean_path}"
    return f"api/v1/fs/{dir_id}"


def build_encrypted_envelope(
    token: str, sig: str, path: str, offset: int | None = None, length: int | None = None
) -> str:
    """Build an encrypted request envelope containing path and params."""
    from .stream import encrypt_json_response

    envelope: dict[str, Any] = {"path": path}
    if offset is not None:
        envelope["offset"] = offset
    if length is not None:
        envelope["length"] = length
    json_bytes = json.dumps(envelope, separators=(",", ":")).encode()
    return encrypt_json_response(token, sig, json_bytes)


def prepare_request_kwargs(
    method: str, url: str, token: str | None, kwargs: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    content = kwargs.get("content", b"")
    if isinstance(content, str):
        kwargs["content"] = content.encode()
    elif kwargs.get("json") is not None:
        kwargs["content"] = json.dumps(kwargs["json"], separators=(",", ":")).encode()
        if "json" in kwargs:
            del kwargs["json"]

    nonce = ""
    if token:
        headers = kwargs.get("headers", {})
        if "X-Signature" not in headers:
            timestamp = str(int(time.time()))
            nonce = secrets.token_hex(8)
            signature = calculate_signature(token, method, url, timestamp, nonce)
            headers.update(
                {"X-Signature": signature, "X-Timestamp": timestamp, "X-Nonce": nonce}
            )
        kwargs["headers"] = headers

    return kwargs, nonce


def prepare_encrypted_request_kwargs(
    method: str,
    url: str,
    token: str,
    path: str,
    offset: int | None = None,
    length: int | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any], str]:
    """Build kwargs for a request with path in encrypted body (token-mode)."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(8)
    signature = calculate_signature(token, method, url, timestamp, nonce)
    envelope = build_encrypted_envelope(token, signature, path, offset, length)
    headers = {
        "X-Signature": signature,
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "Content-Type": "application/vnd.filebridge.request",
    }
    if extra_headers:
        headers.update(extra_headers)
    return {"headers": headers, "content": envelope.encode()}, nonce


def handle_response_errors(status_code: int, text: str):
    if status_code == 401:
        raise AuthenticationError(f"Authentication failed: {text}")
    if status_code == 403:
        raise FileBridgePermissionError(f"Access Forbidden: {text}")
    if status_code == 404:
        raise NotFoundError(f"Not Found: {text}")


def parse_json_response(token: str | None, signature: str | None, body: bytes) -> dict:
    """Parse a JSON response body, decrypting it first when token+signature are present."""
    parsed = json.loads(body)
    if token and signature:
        from .stream import StreamError, decrypt_json_response

        message = parsed.get("message")
        if message is None:
            raise FileBridgeError("Missing 'message' field in encrypted response")
        try:
            json_bytes = decrypt_json_response(token, signature, message)
        except StreamError as e:
            raise FileBridgeError(f"JSON response decryption failed: {e}")
        return json.loads(json_bytes)
    return parsed


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
    from .stream import StreamAead, encode_data, encode_meta, encode_stop

    CHUNK_SIZE = 64 * 1024
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
    from .stream import StreamAead, StreamDecoder, StreamError

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
