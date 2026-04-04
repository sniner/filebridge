"""Tests for Location methods in token mode — encrypted request/response."""

from __future__ import annotations

import json

import httpx
import pytest
from conftest import TOKEN, make_response

from filebridge.client import FileBridgeClient
from filebridge.stream import (
    StreamAead,
    StreamDecoder,
    decrypt_json_response,
    encode_data,
    encode_stop,
    encrypt_json_response,
)


def _client_and_location():
    client = FileBridgeClient("http://test.local")
    loc = client.location("dir1", token=TOKEN)
    return client, loc


def _make_encrypted_json_response(sig: str, data: dict, nonce: str) -> httpx.Response:
    """Build a mock response containing encrypted JSON (as the server would send)."""
    encrypted = encrypt_json_response(TOKEN, sig, json.dumps(data).encode())
    body = json.dumps({"message": encrypted}).encode()
    resp = make_response(200, body, "application/json", nonce=nonce, request_sig=sig)
    return resp


def _make_encrypted_stream_response(sig: str, payload: bytes, nonce: str) -> httpx.Response:
    """Build a mock response containing encrypted stream frames."""
    aead = StreamAead(TOKEN, sig)
    chunk_size = 64 * 1024
    buf = bytearray()
    for i in range(0, len(payload), chunk_size):
        buf.extend(encode_data(aead.encrypt(payload[i : i + chunk_size])))
    buf.extend(encode_stop(aead.finalize()))

    resp = make_response(
        200, bytes(buf), "application/vnd.filebridge.stream", nonce=nonce, request_sig=sig
    )
    return resp


class _RequestCapture:
    """Intercept httpx.Client.request and return a pre-built response."""

    def __init__(self, response_factory):
        self._response_factory = response_factory
        self.calls: list[dict] = []

    def __call__(self, method, url, **kwargs):
        sig = kwargs.get("headers", {}).get("X-Signature", "")
        nonce = kwargs.get("headers", {}).get("X-Nonce", "")
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return self._response_factory(sig, nonce)


# ---------------------------------------------------------------------------
# read (token mode)
# ---------------------------------------------------------------------------


def test_read_token_mode():
    client, loc = _client_and_location()
    payload = b"encrypted file content"

    def response_factory(sig, nonce):
        return _make_encrypted_stream_response(sig, payload, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    result = loc.read("secret.txt")
    assert result == payload

    # Verify request used encrypted body
    call = capture.calls[0]
    assert call["method"] == "GET"
    ct = call["kwargs"]["headers"].get("Content-Type", "")
    assert "vnd.filebridge.request" in ct


def test_read_token_mode_with_range():
    client, loc = _client_and_location()
    payload = b"partial content"

    def response_factory(sig, nonce):
        return _make_encrypted_stream_response(sig, payload, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    result = loc.read("file.bin", offset=100, length=50)
    assert result == payload

    # Verify the encrypted envelope contains offset/length
    call = capture.calls[0]
    body_bytes = call["kwargs"].get("content", b"")
    if isinstance(body_bytes, str):
        body_bytes = body_bytes.encode()
    sig = call["kwargs"]["headers"]["X-Signature"]
    envelope_json = decrypt_json_response(TOKEN, sig, body_bytes.decode())
    envelope = json.loads(envelope_json)
    assert envelope["offset"] == 100
    assert envelope["length"] == 50


# ---------------------------------------------------------------------------
# write (token mode)
# ---------------------------------------------------------------------------


def test_write_token_mode():
    client, loc = _client_and_location()
    data = b"hello encrypted world"

    def response_factory(sig, nonce):
        return make_response(200, b"", "application/json", nonce=nonce, request_sig=sig)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    loc.write("out.txt", data)

    call = capture.calls[0]
    assert call["method"] == "PUT"
    ct = call["kwargs"]["headers"].get("Content-Type", "")
    assert "vnd.filebridge.stream" in ct

    # Verify the stream body can be decoded
    body = call["kwargs"]["content"]
    sig = call["kwargs"]["headers"]["X-Signature"]
    decoder = StreamDecoder()
    decoder.push(body)

    # First frame should be META with encrypted envelope
    frame = decoder.next_frame()
    assert frame is not None
    assert frame.tag == "META"
    envelope_json = decrypt_json_response(TOKEN, sig, frame.payload.decode())
    envelope = json.loads(envelope_json)
    assert envelope["path"] == "out.txt"

    # Then DATA frame(s) + STOP
    aead = StreamAead(TOKEN, sig)
    decrypted = bytearray()
    while True:
        frame = decoder.next_frame()
        assert frame is not None
        if frame.tag == "DATA":
            decrypted.extend(aead.decrypt(frame.payload))
        elif frame.tag == "STOP":
            assert frame.signature is not None
            aead.verify_stop(frame.signature)
            break

    assert bytes(decrypted) == data


def test_write_token_mode_with_offset():
    client, loc = _client_and_location()

    def response_factory(sig, nonce):
        return make_response(200, b"", "application/json", nonce=nonce, request_sig=sig)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    loc.write("file.bin", b"patch", offset=512)

    call = capture.calls[0]
    sig = call["kwargs"]["headers"]["X-Signature"]
    body = call["kwargs"]["content"]
    decoder = StreamDecoder()
    decoder.push(body)
    frame = decoder.next_frame()
    assert frame is not None and frame.tag == "META"
    envelope = json.loads(decrypt_json_response(TOKEN, sig, frame.payload.decode()))
    assert envelope["offset"] == 512


# ---------------------------------------------------------------------------
# list (token mode)
# ---------------------------------------------------------------------------


def test_list_token_mode():
    client, loc = _client_and_location()
    listing = {"items": [{"name": "a.txt", "is_dir": False, "size": 10}]}

    def response_factory(sig, nonce):
        return _make_encrypted_json_response(sig, listing, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    result = list(loc.list())
    assert len(result) == 1
    assert result[0].name == "a.txt"

    call = capture.calls[0]
    ct = call["kwargs"]["headers"].get("Content-Type", "")
    assert "vnd.filebridge.request" in ct


def test_list_token_mode_root():
    """Listing root directory in token mode should work (no subpath)."""
    client, loc = _client_and_location()
    listing = {"items": [{"name": "root.txt", "is_dir": False}]}

    def response_factory(sig, nonce):
        return _make_encrypted_json_response(sig, listing, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    result = list(loc.list(None))
    assert len(result) == 1
    assert result[0].name == "root.txt"


def test_list_token_mode_extensive():
    client, loc = _client_and_location()
    listing = {"items": [{"name": "a.txt", "is_dir": False, "sha256": "abc123"}]}

    def response_factory(sig, nonce):
        return _make_encrypted_json_response(sig, listing, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    result = list(loc.list(extensive=True))
    assert result[0]._stat is not None
    assert result[0]._stat.sha256 == "abc123"

    # Verify the envelope includes extensive flag
    call = capture.calls[0]
    sig = call["kwargs"]["headers"]["X-Signature"]
    body = call["kwargs"].get("content", b"")
    if isinstance(body, str):
        body = body.encode()
    envelope_json = decrypt_json_response(TOKEN, sig, body.decode())
    envelope = json.loads(envelope_json)
    assert envelope.get("extensive") is True


# ---------------------------------------------------------------------------
# info (token mode)
# ---------------------------------------------------------------------------


def test_info_token_mode():
    client, loc = _client_and_location()
    info_data = {"name": "secret.txt", "is_dir": False, "size": 42}

    def response_factory(sig, nonce):
        return _make_encrypted_json_response(sig, info_data, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    meta = loc.info("secret.txt")
    assert meta.name == "secret.txt"
    assert meta.size == 42


def test_info_token_mode_extensive():
    client, loc = _client_and_location()
    info_data = {"name": "file.bin", "is_dir": False, "size": 100, "sha256": "deadbeef"}

    def response_factory(sig, nonce):
        return _make_encrypted_json_response(sig, info_data, nonce)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    meta = loc.info("file.bin", extensive=True)
    assert meta.sha256 == "deadbeef"


# ---------------------------------------------------------------------------
# delete (token mode)
# ---------------------------------------------------------------------------


def test_delete_token_mode():
    client, loc = _client_and_location()

    def response_factory(sig, nonce):
        return make_response(200, b"", "application/json", nonce=nonce, request_sig=sig)

    capture = _RequestCapture(response_factory)
    client.client.request = capture

    loc.delete("bye.txt")

    call = capture.calls[0]
    assert call["method"] == "DELETE"
    ct = call["kwargs"]["headers"].get("Content-Type", "")
    assert "vnd.filebridge.request" in ct

    # Verify envelope contains the path
    sig = call["kwargs"]["headers"]["X-Signature"]
    body = call["kwargs"].get("content", b"")
    if isinstance(body, str):
        body = body.encode()
    envelope_json = decrypt_json_response(TOKEN, sig, body.decode())
    envelope = json.loads(envelope_json)
    assert envelope["path"] == "bye.txt"


# ---------------------------------------------------------------------------
# nonce mismatch
# ---------------------------------------------------------------------------


def test_nonce_mismatch_raises():
    """Server returning wrong nonce should be caught."""
    client, loc = _client_and_location()
    info_data = {"name": "file.txt", "is_dir": False}

    def response_factory(sig, nonce):
        return _make_encrypted_json_response(sig, info_data, "wrong-nonce")

    client.client.request = _RequestCapture(response_factory)

    from filebridge.exceptions import AuthenticationError

    with pytest.raises(AuthenticationError, match="[Nn]once"):
        loc.info("file.txt")
