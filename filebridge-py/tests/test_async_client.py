"""Tests for AsyncLocation methods with AsyncMock — no token, no crypto."""

from __future__ import annotations

import asyncio
import json
import pathlib
from unittest.mock import AsyncMock

import pytest

from conftest import make_response
from filebridge.async_client import AsyncFileBridgeClient, AsyncLocation
from filebridge.exceptions import NotFoundError


def _client_and_location():
    client = AsyncFileBridgeClient("http://test.local")
    loc = client.location("dir1")
    return client, loc


# ---------------------------------------------------------------------------
# client.location()
# ---------------------------------------------------------------------------


def test_async_client_location():
    client = AsyncFileBridgeClient("http://test.local")
    loc = client.location("mydir")
    assert loc.dir_id == "mydir"
    assert loc.token is None


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


def test_async_read_plain_ok():
    async def _coro():
        client, loc = _client_and_location()
        payload = b"async file content"
        mock_resp = make_response(200, payload, "application/octet-stream")
        client.client.request = AsyncMock(return_value=mock_resp)

        result = await loc.read("file.txt")
        assert result == payload

    asyncio.run(_coro())


def test_async_read_not_found():
    async def _coro():
        client, loc = _client_and_location()
        mock_resp = make_response(404, b"not found", "text/plain")
        client.client.request = AsyncMock(return_value=mock_resp)

        with pytest.raises(NotFoundError):
            await loc.read("missing.txt")

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------


def test_async_write_plain_ok():
    async def _coro():
        client, loc = _client_and_location()
        mock_resp = make_response(200, b"", "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        await loc.write("out.txt", b"async bytes")
        client.client.request.assert_awaited_once()

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def test_async_list_ok():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps(
            {"items": [{"name": "b.txt", "is_dir": False, "size": 5}]}
        ).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        result = await loc.list()
        assert len(result) == 1
        assert result[0].name == "b.txt"

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------


def test_async_info_ok():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps({"name": "async_info.txt", "is_dir": False, "size": 99}).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        meta = await loc.info("async_info.txt")
        assert meta.name == "async_info.txt"
        assert meta.size == 99

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# exists
# ---------------------------------------------------------------------------


def test_async_exists_true():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps({"name": "here.txt", "is_dir": False}).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        assert await loc.exists("here.txt") is True

    asyncio.run(_coro())


def test_async_exists_false():
    async def _coro():
        client, loc = _client_and_location()
        mock_resp = make_response(404, b"not found", "text/plain")
        client.client.request = AsyncMock(return_value=mock_resp)

        assert await loc.exists("gone.txt") is False

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------


def test_async_delete_ok():
    async def _coro():
        client, loc = _client_and_location()
        mock_resp = make_response(200, b"", "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        await loc.delete("gone.txt")  # must not raise

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# read_stream alias
# ---------------------------------------------------------------------------


def test_async_read_stream_alias():
    assert AsyncLocation.stream_read is AsyncLocation.read_stream


# ---------------------------------------------------------------------------
# pathlike accepted
# ---------------------------------------------------------------------------


def test_async_pathlike_accepted():
    async def _coro():
        client, loc = _client_and_location()
        payload = b"async file content"
        mock_resp = make_response(200, payload, "application/octet-stream")
        client.client.request = AsyncMock(return_value=mock_resp)

        result = await loc.read(pathlib.PurePosixPath("file.txt"))
        assert result == payload

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# iterdir
# ---------------------------------------------------------------------------


def test_async_iterdir_yields_all_items():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps(
            {"items": [
                {"name": "x.txt", "is_dir": False, "size": 10},
                {"name": "y.txt", "is_dir": False, "size": 20},
            ]}
        ).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        items = [item async for item in loc.iterdir()]
        assert len(items) == 2
        assert {m.name for m in items} == {"x.txt", "y.txt"}

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# glob
# ---------------------------------------------------------------------------


def test_async_glob_matches_pattern():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps(
            {"items": [
                {"name": "foo.txt", "is_dir": False},
                {"name": "bar.txt", "is_dir": False},
                {"name": "baz.log", "is_dir": False},
            ]}
        ).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        items = [item async for item in loc.glob("*.txt")]
        assert {m.name for m in items} == {"foo.txt", "bar.txt"}

    asyncio.run(_coro())


def test_async_glob_excludes_dirs():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps(
            {"items": [
                {"name": "file.txt", "is_dir": False},
                {"name": "subdir.txt", "is_dir": True},
            ]}
        ).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        items = [item async for item in loc.glob("*.txt")]
        assert len(items) == 1
        assert items[0].name == "file.txt"

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# walk
# ---------------------------------------------------------------------------


def test_async_walk_flat():
    async def _coro():
        client, loc = _client_and_location()
        body = json.dumps(
            {"items": [
                {"name": "a.txt", "is_dir": False},
                {"name": "b.txt", "is_dir": False},
            ]}
        ).encode()
        mock_resp = make_response(200, body, "application/json")
        client.client.request = AsyncMock(return_value=mock_resp)

        entries = [entry async for entry in loc.walk()]
        assert len(entries) == 1
        dirpath, subdirs, files = entries[0]
        assert dirpath == ""
        assert subdirs == []
        assert {m.name for m in files} == {"a.txt", "b.txt"}

    asyncio.run(_coro())


# ---------------------------------------------------------------------------
# open (write mode)
# ---------------------------------------------------------------------------


def test_async_open_write_flushes_on_close():
    async def _coro():
        client, loc = _client_and_location()
        received = []
        mock_resp = make_response(200, b"", "application/json")

        async def fake_request(method, url, **kwargs):
            received.append(kwargs.get("content"))
            return mock_resp

        client.client.request = fake_request

        async with loc.open("file.txt", "w") as f:
            await f.write(b"small data")

        assert len(received) == 1
        assert received[0] == b"small data"

    asyncio.run(_coro())


def test_async_open_write_auto_flushes_at_chunk_boundary():
    async def _coro():
        client, loc = _client_and_location()
        received = []
        mock_resp = make_response(200, b"", "application/json")

        async def fake_request(method, url, **kwargs):
            received.append(kwargs.get("content"))
            return mock_resp

        client.client.request = fake_request

        chunk_64k = b"x" * (64 * 1024)
        tail = b"y" * (16 * 1024)

        async with loc.open("file.txt", "w") as f:
            await f.write(chunk_64k + tail)

        assert len(received) == 2
        assert received[0] == chunk_64k
        assert received[1] == tail

    asyncio.run(_coro())


def test_async_open_write_accepts_str():
    async def _coro():
        client, loc = _client_and_location()
        received = []
        mock_resp = make_response(200, b"", "application/json")

        async def fake_request(method, url, **kwargs):
            received.append(kwargs.get("content"))
            return mock_resp

        client.client.request = fake_request

        async with loc.open("file.txt", "w") as f:
            await f.write("hello async text")

        assert received[0] == b"hello async text"

    asyncio.run(_coro())


def test_async_walk_nested():
    async def _coro():
        client, loc = _client_and_location()
        responses = [
            json.dumps({"items": [
                {"name": "subdir", "is_dir": True},
                {"name": "root.txt", "is_dir": False},
            ]}).encode(),
            json.dumps({"items": [
                {"name": "child.txt", "is_dir": False},
            ]}).encode(),
        ]
        call_count = [0]

        async def fake_request(method, url, **kwargs):
            body = responses[call_count[0] % len(responses)]
            call_count[0] += 1
            return make_response(200, body, "application/json")

        client.client.request = fake_request

        entries = [entry async for entry in loc.walk()]
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

    asyncio.run(_coro())
