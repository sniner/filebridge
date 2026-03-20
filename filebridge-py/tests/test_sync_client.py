"""Tests for Location methods with mocked httpx.Client — no token, no crypto."""

from __future__ import annotations

import json
import pathlib

import pytest

from conftest import make_response
from filebridge.exceptions import AuthenticationError, NotFoundError
from filebridge.sync_client import FileBridgeClient, Location


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


# ---------------------------------------------------------------------------
# read_stream alias
# ---------------------------------------------------------------------------


def test_read_stream_alias():
    assert Location.stream_read is Location.read_stream


# ---------------------------------------------------------------------------
# pathlike accepted
# ---------------------------------------------------------------------------


def test_pathlike_accepted():
    client, loc = _client_and_location()
    payload = b"file content"
    mock_resp = make_response(200, payload, "application/octet-stream")
    client.client.request = lambda *a, **kw: mock_resp

    result = loc.read(pathlib.PurePosixPath("file.txt"))
    assert result == payload


# ---------------------------------------------------------------------------
# iterdir
# ---------------------------------------------------------------------------


def test_iterdir_yields_all_items():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [
            {"name": "a.txt", "is_dir": False, "size": 10},
            {"name": "b.txt", "is_dir": False, "size": 20},
        ]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.iterdir())
    assert len(items) == 2
    assert {m.name for m in items} == {"a.txt", "b.txt"}


# ---------------------------------------------------------------------------
# glob
# ---------------------------------------------------------------------------


def test_glob_matches_pattern():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [
            {"name": "foo.txt", "is_dir": False},
            {"name": "bar.txt", "is_dir": False},
            {"name": "baz.log", "is_dir": False},
        ]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt"))
    assert {m.name for m in items} == {"foo.txt", "bar.txt"}


def test_glob_excludes_dirs():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [
            {"name": "file.txt", "is_dir": False},
            {"name": "subdir.txt", "is_dir": True},
        ]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt"))
    assert len(items) == 1
    assert items[0].name == "file.txt"


def test_glob_case_insensitive():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [
            {"name": "README.TXT", "is_dir": False},
            {"name": "notes.txt", "is_dir": False},
            {"name": "image.PNG", "is_dir": False},
        ]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt", case_sensitive=False))
    assert {m.name for m in items} == {"README.TXT", "notes.txt"}


def test_glob_case_sensitive_default():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [
            {"name": "README.TXT", "is_dir": False},
            {"name": "notes.txt", "is_dir": False},
        ]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt"))  # case_sensitive=True by default
    assert [m.name for m in items] == ["notes.txt"]


# ---------------------------------------------------------------------------
# stat
# ---------------------------------------------------------------------------


def test_stat_returns_metadata():
    client, loc = _client_and_location()
    body = json.dumps({"name": "file.txt", "is_dir": False, "size": 42}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    meta = loc.stat("file.txt")
    assert meta.name == "file.txt"
    assert meta.size == 42


def test_stat_forwards_extensive():
    client, loc = _client_and_location()
    received = {}
    body = json.dumps(
        {"name": "file.txt", "is_dir": False, "sha256": "deadbeef"}
    ).encode()
    mock_resp = make_response(200, body, "application/json")

    def fake_request(method, url, **kwargs):
        received["params"] = kwargs.get("params", {})
        return mock_resp

    client.client.request = fake_request
    meta = loc.stat("file.txt", extensive=True)
    assert meta.sha256 == "deadbeef"
    assert received["params"].get("extensive") == "true"


# ---------------------------------------------------------------------------
# info — extensive
# ---------------------------------------------------------------------------


def test_info_extensive_sends_param_and_returns_sha256():
    client, loc = _client_and_location()
    received = {}
    body = json.dumps(
        {"name": "data.bin", "is_dir": False, "size": 100, "sha256": "cafebabe"}
    ).encode()
    mock_resp = make_response(200, body, "application/json")

    def fake_request(method, url, **kwargs):
        received["params"] = kwargs.get("params", {})
        return mock_resp

    client.client.request = fake_request
    meta = loc.info("data.bin", extensive=True)

    assert meta.sha256 == "cafebabe"
    assert received["params"].get("extensive") == "true"


def test_info_no_extensive_param_by_default():
    client, loc = _client_and_location()
    received = {}
    body = json.dumps({"name": "data.bin", "is_dir": False}).encode()
    mock_resp = make_response(200, body, "application/json")

    def fake_request(method, url, **kwargs):
        received["params"] = kwargs.get("params", {})
        return mock_resp

    client.client.request = fake_request
    loc.info("data.bin")

    assert "extensive" not in received.get("params", {})


# ---------------------------------------------------------------------------
# walk
# ---------------------------------------------------------------------------


def test_walk_flat():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [
            {"name": "a.txt", "is_dir": False},
            {"name": "b.txt", "is_dir": False},
        ]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    entries = list(loc.walk())
    assert len(entries) == 1
    dirpath, subdirs, files = entries[0]
    assert dirpath == ""
    assert subdirs == []
    assert {m.name for m in files} == {"a.txt", "b.txt"}


# ---------------------------------------------------------------------------
# open (write mode)
# ---------------------------------------------------------------------------


def test_open_write_flushes_on_close():
    client, loc = _client_and_location()
    received = []
    mock_resp = make_response(200, b"", "application/json")

    def fake_request(method, url, **kwargs):
        received.append(kwargs.get("content"))
        return mock_resp

    client.client.request = fake_request

    with loc.open("file.txt", "w") as f:
        f.write(b"small data")  # < 64 KB, no auto-flush

    assert len(received) == 1
    assert received[0] == b"small data"


def test_open_write_auto_flushes_at_chunk_boundary():
    client, loc = _client_and_location()
    received = []
    mock_resp = make_response(200, b"", "application/json")

    def fake_request(method, url, **kwargs):
        received.append(kwargs.get("content"))
        return mock_resp

    client.client.request = fake_request

    chunk_64k = b"x" * (64 * 1024)
    tail = b"y" * (16 * 1024)

    with loc.open("file.txt", "w") as f:
        f.write(chunk_64k + tail)  # 80 KB: one auto-flush + close flush

    assert len(received) == 2
    assert received[0] == chunk_64k
    assert received[1] == tail


def test_open_write_flush_sends_partial_buffer():
    client, loc = _client_and_location()
    received = []
    mock_resp = make_response(200, b"", "application/json")

    def fake_request(method, url, **kwargs):
        received.append(kwargs.get("content"))
        return mock_resp

    client.client.request = fake_request

    with loc.open("file.txt", "w") as f:
        f.write(b"first")
        f.flush()
        f.write(b"second")

    assert received == [b"first", b"second"]


def test_open_write_accepts_str():
    client, loc = _client_and_location()
    received = []
    mock_resp = make_response(200, b"", "application/json")

    def fake_request(method, url, **kwargs):
        received.append(kwargs.get("content"))
        return mock_resp

    client.client.request = fake_request

    with loc.open("file.txt", "w") as f:
        f.write("hello text")

    assert received[0] == b"hello text"


def test_walk_nested():
    client, loc = _client_and_location()
    responses = [
        # Root: one dir, one file
        json.dumps({"items": [
            {"name": "subdir", "is_dir": True},
            {"name": "root.txt", "is_dir": False},
        ]}).encode(),
        # subdir: one file
        json.dumps({"items": [
            {"name": "child.txt", "is_dir": False},
        ]}).encode(),
    ]
    call_count = [0]

    def fake_request(method, url, **kwargs):
        body = responses[call_count[0] % len(responses)]
        call_count[0] += 1
        return make_response(200, body, "application/json")

    client.client.request = fake_request

    entries = list(loc.walk())
    assert len(entries) == 2

    dirpath0, subdirs0, files0 = entries[0]
    assert dirpath0 == ""
    assert len(subdirs0) == 1
    assert subdirs0[0].name == "subdir"
    assert len(files0) == 1
    assert files0[0].name == "root.txt"

    dirpath1, subdirs1, files1 = entries[1]
    assert dirpath1 == "subdir"
    assert subdirs1 == []
    assert len(files1) == 1
    assert files1[0].name == "child.txt"
