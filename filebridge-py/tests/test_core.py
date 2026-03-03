"""Unit tests for pure functions in core.py — no network calls, no mocks."""

from __future__ import annotations

import json

import pytest

from conftest import SIGNATURE, TOKEN
from filebridge.core import (
    build_encrypted_write_body,
    calculate_signature,
    decode_read_response,
    decode_verified_stream_content,
    get_api_path,
    handle_response_errors,
    prepare_request_kwargs,
)
from filebridge.exceptions import (
    AuthenticationError,
    FileBridgeError,
    FileBridgePermissionError,
    IsDirectoryError,
    NotFoundError,
)


# ---------------------------------------------------------------------------
# get_api_path
# ---------------------------------------------------------------------------


def test_get_api_path_basic():
    assert get_api_path("DIR", "file.txt") == "api/v1/fs/DIR/file.txt"


def test_get_api_path_leading_slash():
    assert get_api_path("DIR", "/file.txt") == "api/v1/fs/DIR/file.txt"


def test_get_api_path_none():
    assert get_api_path("DIR", None) == "api/v1/fs/DIR"


def test_get_api_path_empty():
    assert get_api_path("DIR", "") == "api/v1/fs/DIR"


def test_get_api_path_subdir():
    assert get_api_path("DIR", "a/b/c") == "api/v1/fs/DIR/a/b/c"


# ---------------------------------------------------------------------------
# calculate_signature
# ---------------------------------------------------------------------------


def test_calculate_signature_no_token():
    result = calculate_signature(None, "GET", "http://example.com/path", "123", "abc")
    assert result == ""


def test_calculate_signature_deterministic():
    sig1 = calculate_signature(TOKEN, "GET", "http://example.com/path", "123", "nonce1")
    sig2 = calculate_signature(TOKEN, "GET", "http://example.com/path", "123", "nonce1")
    assert sig1 == sig2
    assert len(sig1) == 64  # sha256 hex digest


def test_calculate_signature_method_diff():
    sig_get = calculate_signature(TOKEN, "GET", "http://example.com/path", "123", "n")
    sig_put = calculate_signature(TOKEN, "PUT", "http://example.com/path", "123", "n")
    assert sig_get != sig_put


# ---------------------------------------------------------------------------
# prepare_request_kwargs
# ---------------------------------------------------------------------------


def test_prepare_request_kwargs_no_token():
    kwargs, nonce = prepare_request_kwargs("GET", "http://example.com/", None, {})
    assert nonce == ""
    assert "headers" not in kwargs


def test_prepare_request_kwargs_with_token():
    kwargs, nonce = prepare_request_kwargs("GET", "http://example.com/path", TOKEN, {})
    headers = kwargs["headers"]
    assert "X-Signature" in headers
    assert "X-Timestamp" in headers
    assert "X-Nonce" in headers
    assert nonce != ""


def test_prepare_request_kwargs_nonce_unique():
    _, nonce1 = prepare_request_kwargs("GET", "http://example.com/path", TOKEN, {})
    _, nonce2 = prepare_request_kwargs("GET", "http://example.com/path", TOKEN, {})
    assert nonce1 != nonce2


def test_prepare_request_kwargs_nonce_returned():
    kwargs, nonce = prepare_request_kwargs("GET", "http://example.com/path", TOKEN, {})
    assert nonce == kwargs["headers"]["X-Nonce"]


# ---------------------------------------------------------------------------
# handle_response_errors
# ---------------------------------------------------------------------------


def test_handle_response_errors_401():
    with pytest.raises(AuthenticationError):
        handle_response_errors(401, "Unauthorized")


def test_handle_response_errors_403():
    with pytest.raises(FileBridgePermissionError):
        handle_response_errors(403, "Forbidden")


def test_handle_response_errors_404():
    with pytest.raises(NotFoundError):
        handle_response_errors(404, "Not Found")


def test_handle_response_errors_500():
    # 500 is not handled — must not raise
    handle_response_errors(500, "Internal Server Error")


# ---------------------------------------------------------------------------
# decode_read_response
# ---------------------------------------------------------------------------


def test_decode_read_response_octet_stream():
    data = b"raw binary data"
    result = decode_read_response(None, "application/octet-stream", data, None, "file.bin")
    assert result == data


def test_decode_read_response_json_directory():
    content = json.dumps({"items": [{"name": "f.txt", "is_dir": False, "size": 10}]}).encode()
    with pytest.raises(IsDirectoryError):
        decode_read_response(None, "application/json", content, None, "somedir")


def test_decode_read_response_stream_no_sig():
    with pytest.raises(FileBridgeError, match="Missing signature"):
        decode_read_response(TOKEN, "application/vnd.filebridge.stream", b"data", None, "f.txt")


def test_decode_read_response_stream_roundtrip():
    original = b"test content for stream roundtrip"
    encrypted = build_encrypted_write_body(TOKEN, SIGNATURE, original)
    result = decode_read_response(
        TOKEN, "application/vnd.filebridge.stream", encrypted, SIGNATURE, "f.txt"
    )
    assert result == original


# ---------------------------------------------------------------------------
# build_encrypted_write_body
# ---------------------------------------------------------------------------


def test_build_encrypted_write_body_roundtrip():
    data = b"some test data for write body"
    encrypted = build_encrypted_write_body(TOKEN, SIGNATURE, data)
    result = decode_verified_stream_content(TOKEN, SIGNATURE, encrypted)
    assert result == data


def test_build_encrypted_write_body_empty():
    encrypted = build_encrypted_write_body(TOKEN, SIGNATURE, b"")
    result = decode_verified_stream_content(TOKEN, SIGNATURE, encrypted)
    assert result == b""
