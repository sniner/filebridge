"""Shared test helpers and constants."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock

import httpx

TOKEN = "test-secret"
SIGNATURE = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"


def make_response(
    status_code: int,
    content: bytes | str,
    content_type: str,
    nonce: str | None = None,
    request_sig: str | None = None,
) -> MagicMock:
    """Return a MagicMock resembling an httpx.Response for client and IO tests."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.is_success = 200 <= status_code < 300
    if isinstance(content, str):
        content = content.encode()
    mock.content = content
    mock.text = content.decode("utf-8", errors="replace")
    mock.read = lambda: content
    mock.iter_bytes = lambda chunk_size=None: iter([content] if content else [])

    resp_headers: dict[str, str] = {"Content-Type": content_type}
    if nonce is not None:
        resp_headers["X-Nonce"] = nonce
    mock.headers = httpx.Headers(resp_headers)

    req_headers: dict[str, str] = {}
    if request_sig is not None:
        req_headers["X-Signature"] = request_sig
    mock.request = MagicMock()
    mock.request.headers = httpx.Headers(req_headers)

    return mock


def fake_requests(client, handler) -> None:
    """Make *client* answer every request with the response *handler* returns.

    The package sends a request with ``request`` or with ``stream``, depending
    on what it expects in return. Both are replaced.
    """

    @contextmanager
    def stream(method, url, **kwargs):
        yield handler(method, url, **kwargs)

    client.client.request = handler
    client.client.stream = stream
