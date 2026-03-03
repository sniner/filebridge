"""Tests for Location methods with mocked httpx.Client — no token, no crypto."""

from __future__ import annotations

import json

import pytest

from conftest import make_response
from filebridge.exceptions import AuthenticationError, NotFoundError
from filebridge.sync_client import FileBridgeClient


def _client_and_location():
    client = FileBridgeClient("http://test.local")
    loc = client.location("dir1")
    return client, loc


# ---------------------------------------------------------------------------
# client.location()
# ---------------------------------------------------------------------------


def test_client_location():
    client = FileBridgeClient("http://test.local")
    loc = client.location("mydir")
    assert loc.dir_id == "mydir"
    assert loc.token is None


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


def test_read_plain_ok():
    client, loc = _client_and_location()
    payload = b"file content"
    mock_resp = make_response(200, payload, "application/octet-stream")
    client.client.request = lambda *a, **kw: mock_resp

    result = loc.read("file.txt")
    assert result == payload


def test_read_not_found():
    client, loc = _client_and_location()
    mock_resp = make_response(404, b"not found", "text/plain")
    client.client.request = lambda *a, **kw: mock_resp

    with pytest.raises(NotFoundError):
        loc.read("missing.txt")


def test_read_unauthorized():
    client, loc = _client_and_location()
    mock_resp = make_response(401, b"unauthorized", "text/plain")
    client.client.request = lambda *a, **kw: mock_resp

    with pytest.raises(AuthenticationError):
        loc.read("secret.txt")


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------


def test_write_plain_ok():
    client, loc = _client_and_location()
    mock_resp = make_response(200, b"", "application/json")
    received: list[dict] = []

    def fake_request(method, url, **kwargs):
        received.append({"method": method, "content": kwargs.get("content")})
        return mock_resp

    client.client.request = fake_request
    loc.write("out.txt", b"hello bytes")

    assert len(received) == 1
    assert received[0]["method"] == "PUT"
    assert received[0]["content"] == b"hello bytes"


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_list_ok():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [{"name": "a.txt", "is_dir": False, "size": 10}]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    result = loc.list()
    assert len(result) == 1
    assert result[0].name == "a.txt"
    assert result[0].is_dir is False


def test_list_single_file():
    client, loc = _client_and_location()
    body = json.dumps({"name": "solo.txt", "is_dir": False}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    result = loc.list()
    assert len(result) == 1
    assert result[0].name == "solo.txt"


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def test_info_ok():
    client, loc = _client_and_location()
    body = json.dumps({"name": "info.txt", "is_dir": False, "size": 42}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    meta = loc.info("info.txt")
    assert meta.name == "info.txt"
    assert meta.size == 42


# ---------------------------------------------------------------------------
# exists
# ---------------------------------------------------------------------------


def test_exists_true():
    client, loc = _client_and_location()
    body = json.dumps({"name": "present.txt", "is_dir": False}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    assert loc.exists("present.txt") is True


def test_exists_false():
    client, loc = _client_and_location()
    mock_resp = make_response(404, b"not found", "text/plain")
    client.client.request = lambda *a, **kw: mock_resp

    assert loc.exists("ghost.txt") is False


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_delete_ok():
    client, loc = _client_and_location()
    mock_resp = make_response(200, b"", "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    loc.delete("bye.txt")  # must not raise
