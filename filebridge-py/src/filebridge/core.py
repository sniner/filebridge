"""Low-level request building and response handling for the Filebridge API."""

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
    FileBridgePermissionError,
    NotFoundError,
)
from .stream import build_encrypted_envelope


def calculate_signature(
    token: str | None, method: str, url: str, timestamp: str, nonce: str
) -> str:
    """Compute the HMAC-SHA256 request signature. Returns ``""`` if no token."""
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


def prepare_request_kwargs(
    method: str, url: str, token: str | None, kwargs: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    """Add authentication headers to request kwargs. Returns ``(kwargs, nonce)``."""
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
    extensive: bool = False,
) -> tuple[dict[str, Any], str]:
    """Build kwargs for a request with path in encrypted body (token-mode)."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(8)
    signature = calculate_signature(token, method, url, timestamp, nonce)
    envelope = build_encrypted_envelope(token, signature, path, offset, length, extensive)
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
    """Raise a typed exception for known HTTP error status codes."""
    if status_code == 401:
        raise AuthenticationError(text)
    if status_code == 403:
        raise FileBridgePermissionError(text)
    if status_code == 404:
        raise NotFoundError(text)
