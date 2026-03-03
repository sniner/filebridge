"""Tests for AsyncLocation methods with AsyncMock — no token, no crypto."""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import pytest

from conftest import make_response
from filebridge.async_client import AsyncFileBridgeClient
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
