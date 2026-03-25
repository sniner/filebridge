"""Tests for Location methods with mocked httpx.Client — no token, no crypto."""

from __future__ import annotations

import json
import pathlib

import pytest
from conftest import make_response

from filebridge.client import FileBridgeClient, Location, LocationEntry
from filebridge.exceptions import AuthenticationError, NotFoundError


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


def test_client_at_alias():
    client = FileBridgeClient("http://test.local")
    loc = client.at("mydir", token="secret")
    assert loc.dir_id == "mydir"
    assert loc.token == "secret"
    assert FileBridgeClient.at is FileBridgeClient.location


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
    body = json.dumps({"items": [{"name": "a.txt", "is_dir": False, "size": 10}]}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    result = list(loc.list())
    assert len(result) == 1
    assert result[0].name == "a.txt"
    assert result[0].is_dir() is False


def test_list_single_file():
    client, loc = _client_and_location()
    body = json.dumps({"name": "solo.txt", "is_dir": False}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    result = list(loc.list())
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
        {
            "items": [
                {"name": "a.txt", "is_dir": False, "size": 10},
                {"name": "b.txt", "is_dir": False, "size": 20},
            ]
        }
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
        {
            "items": [
                {"name": "foo.txt", "is_dir": False},
                {"name": "bar.txt", "is_dir": False},
                {"name": "baz.log", "is_dir": False},
            ]
        }
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt"))
    assert {m.name for m in items} == {"foo.txt", "bar.txt"}


def test_glob_includes_dirs():
    """glob matches both files and directories (pathlib-compatible behavior)."""
    client, loc = _client_and_location()
    body = json.dumps(
        {
            "items": [
                {"name": "file.txt", "is_dir": False},
                {"name": "subdir.txt", "is_dir": True},
            ]
        }
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt"))
    assert len(items) == 2
    assert {m.name for m in items} == {"file.txt", "subdir.txt"}


def test_glob_case_insensitive():
    client, loc = _client_and_location()
    body = json.dumps(
        {
            "items": [
                {"name": "README.TXT", "is_dir": False},
                {"name": "notes.txt", "is_dir": False},
                {"name": "image.PNG", "is_dir": False},
            ]
        }
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    items = list(loc.glob("*.txt", case_sensitive=False))
    assert {m.name for m in items} == {"README.TXT", "notes.txt"}


def test_glob_case_sensitive_default():
    client, loc = _client_and_location()
    body = json.dumps(
        {
            "items": [
                {"name": "README.TXT", "is_dir": False},
                {"name": "notes.txt", "is_dir": False},
            ]
        }
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
    body = json.dumps({"name": "file.txt", "is_dir": False, "sha256": "deadbeef"}).encode()
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
        {
            "items": [
                {"name": "a.txt", "is_dir": False},
                {"name": "b.txt", "is_dir": False},
            ]
        }
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    entries = list(loc.walk())
    assert len(entries) == 1
    dirpath, subdirs, files = entries[0]
    assert dirpath == pathlib.PurePosixPath(".")
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
        json.dumps(
            {
                "items": [
                    {"name": "subdir", "is_dir": True},
                    {"name": "root.txt", "is_dir": False},
                ]
            }
        ).encode(),
        # subdir: one file
        json.dumps(
            {
                "items": [
                    {"name": "child.txt", "is_dir": False},
                ]
            }
        ).encode(),
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
    assert dirpath0 == pathlib.PurePosixPath(".")
    assert len(subdirs0) == 1
    assert subdirs0[0].name == "subdir"
    assert len(files0) == 1
    assert files0[0].name == "root.txt"

    dirpath1, subdirs1, files1 = entries[1]
    assert dirpath1 == pathlib.PurePosixPath("subdir")
    assert subdirs1 == []
    assert len(files1) == 1
    assert files1[0].name == "child.txt"


# ---------------------------------------------------------------------------
# LocationEntry
# ---------------------------------------------------------------------------


def _make_entry(loc, path, is_dir=False):
    from filebridge.models import Metadata

    return LocationEntry(loc, pathlib.PurePosixPath(path), Metadata(name=pathlib.PurePosixPath(path).name, is_dir=is_dir))


def test_location_entry_properties():
    client, loc = _client_and_location()
    entry = _make_entry(loc, "docs/readme.tar.gz")
    assert entry.name == "readme.tar.gz"
    assert entry.stem == "readme.tar"
    assert entry.suffix == ".gz"
    assert entry.suffixes == [".tar", ".gz"]
    assert entry.is_file() is True
    assert entry.is_dir() is False
    assert entry.path == pathlib.PurePosixPath("docs/readme.tar.gz")
    assert entry.location is loc


def test_location_entry_fspath():
    client, loc = _client_and_location()
    entry = _make_entry(loc, "some/file.txt")
    assert entry.__fspath__() == "some/file.txt"


def test_location_entry_str_repr():
    client, loc = _client_and_location()
    entry = _make_entry(loc, "file.txt")
    assert str(entry) == "file.txt"
    assert "file.txt" in repr(entry)


def test_location_entry_truediv():
    """__truediv__ makes a network call to get metadata for the combined path."""
    client, loc = _client_and_location()
    body = json.dumps({"name": "child.txt", "is_dir": False, "size": 5}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    parent = _make_entry(loc, "docs", is_dir=True)
    child = parent / "child.txt"
    assert child.name == "child.txt"
    assert child.path == pathlib.PurePosixPath("docs/child.txt")


def test_location_entry_iterdir_file_raises():
    """iterdir() on a file entry should raise NotADirectoryError."""
    client, loc = _client_and_location()
    entry = _make_entry(loc, "file.txt", is_dir=False)
    with pytest.raises(NotADirectoryError):
        list(entry.iterdir())


def test_location_entry_iterdir_dir():
    client, loc = _client_and_location()
    body = json.dumps(
        {"items": [{"name": "a.txt", "is_dir": False}]}
    ).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    entry = _make_entry(loc, "mydir", is_dir=True)
    items = list(entry.iterdir())
    assert len(items) == 1
    assert items[0].name == "a.txt"


def test_location_entry_stat():
    client, loc = _client_and_location()
    body = json.dumps({"name": "file.txt", "is_dir": False, "size": 99}).encode()
    mock_resp = make_response(200, body, "application/json")
    client.client.request = lambda *a, **kw: mock_resp

    entry = LocationEntry(loc, "file.txt")
    meta = entry.stat()
    assert meta.size == 99


def test_location_entry_eq_case_sensitive_default():
    client, loc = _client_and_location()
    loc._case_sensitive = True  # Default
    entry1 = _make_entry(loc, "Docs/README.txt")
    entry2 = _make_entry(loc, "docs/readme.txt")
    entry3 = _make_entry(loc, "Docs/README.txt")

    assert entry1 != entry2
    assert entry1 == entry3


def test_location_entry_eq_case_insensitive():
    client, loc = _client_and_location()
    loc._case_sensitive = False
    entry1 = _make_entry(loc, "Docs/README.txt")
    entry2 = _make_entry(loc, "docs/readme.txt")
    entry3 = _make_entry(loc, "DOCS/Readme.TXT")

    assert entry1 == entry2
    assert entry2 == entry3


def test_location_entry_eq_case_insensitive_different_depth():
    """Case-insensitive __eq__ must not treat 'a/b' == 'a/b/c' as equal."""
    client, loc = _client_and_location()
    loc._case_sensitive = False
    short = _make_entry(loc, "Docs/README.txt")
    long = _make_entry(loc, "Docs/README.txt/extra")

    assert short != long
    assert long != short


def test_location_entry_hash_case_sensitive():
    client, loc = _client_and_location()
    loc._case_sensitive = True
    e1 = _make_entry(loc, "Docs/README.txt")
    e2 = _make_entry(loc, "Docs/README.txt")
    e3 = _make_entry(loc, "docs/readme.txt")

    # Equal entries must have equal hashes
    assert hash(e1) == hash(e2)
    # Usable in set
    s = {e1, e2}
    assert len(s) == 1
    # Different case → different entry in case-sensitive mode
    s.add(e3)
    assert len(s) == 2


def test_location_entry_hash_case_insensitive():
    client, loc = _client_and_location()
    loc._case_sensitive = False
    e1 = _make_entry(loc, "Docs/README.txt")
    e2 = _make_entry(loc, "docs/readme.txt")

    assert e1 == e2
    assert hash(e1) == hash(e2)
    # Same entry in set
    s = {e1, e2}
    assert len(s) == 1


def test_location_entry_hash_as_dict_key():
    client, loc = _client_and_location()
    e1 = _make_entry(loc, "file.txt")
    d = {e1: "value"}
    e2 = _make_entry(loc, "file.txt")
    assert d[e2] == "value"


def test_location_entry_repr_format():
    client, loc = _client_and_location()
    entry = _make_entry(loc, "some/file.txt")
    r = repr(entry)
    assert r.startswith("LocationEntry(")
    assert "file.txt" in r


def test_open_write_no_flush_on_exception():
    """_WriteHandle must not flush when the with-block raises."""
    client, loc = _client_and_location()
    write_calls = []
    mock_resp = make_response(200, b"", "application/json")

    def fake_request(method, url, **kwargs):
        write_calls.append(kwargs.get("content"))
        return mock_resp

    client.client.request = fake_request

    with pytest.raises(RuntimeError):
        with loc.open("file.txt", "w") as f:
            f.write(b"buffered data")
            raise RuntimeError("simulated error")

    # No write should have been flushed
    assert len(write_calls) == 0


def test_location_entry_is_relative_to_case_sensitive():
    client, loc = _client_and_location()
    loc._case_sensitive = True
    parent = _make_entry(loc, "Docs")
    child_match = _make_entry(loc, "Docs/README.txt")
    child_mismatch = _make_entry(loc, "docs/README.txt")

    assert child_match.is_relative_to(parent) is True
    assert child_mismatch.is_relative_to(parent) is False


def test_location_entry_is_relative_to_case_insensitive():
    client, loc = _client_and_location()
    loc._case_sensitive = False
    parent = _make_entry(loc, "Docs")
    child_match = _make_entry(loc, "Docs/README.txt")
    child_insensitive = _make_entry(loc, "docs/README.txt")

    assert child_match.is_relative_to(parent) is True
    assert child_insensitive.is_relative_to(parent) is True


# ---------------------------------------------------------------------------
# Location equality
# ---------------------------------------------------------------------------


def test_location_eq_same():
    client = FileBridgeClient("http://test.local")
    loc1 = client.location("dir1", token="tok")
    loc2 = client.location("dir1", token="tok")
    assert loc1 == loc2
    assert hash(loc1) == hash(loc2)


def test_location_eq_different_dir():
    client = FileBridgeClient("http://test.local")
    loc1 = client.location("dir1")
    loc2 = client.location("dir2")
    assert loc1 != loc2


def test_location_repr_no_token():
    client = FileBridgeClient("http://test.local")
    loc = client.location("dir1", token="secret-token")
    r = repr(loc)
    assert "dir1" in r
    assert "secret" not in r
