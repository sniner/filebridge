"""Tests for FileBridgeReadStream and AsyncFileBridgeReadStream."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from conftest import SIGNATURE, TOKEN
from filebridge.exceptions import FileBridgeError
from filebridge.io import AsyncFileBridgeReadStream, FileBridgeReadStream
from filebridge.stream import StreamAead, encode_data, encode_stop


def _make_plain_response(chunks: list[bytes]) -> MagicMock:
    resp = MagicMock()
    resp.headers = httpx.Headers({"Content-Type": "application/octet-stream"})
    resp.request = MagicMock()
    resp.request.headers = httpx.Headers({})
    resp.iter_bytes = MagicMock(return_value=iter(chunks))
    resp.close = MagicMock()
    return resp


def _make_verified_frames(data: bytes) -> bytes:
    aead = StreamAead(TOKEN, SIGNATURE)
    return encode_data(aead.encrypt(data)) + encode_stop(aead.finalize())


def _make_verified_response(data: bytes) -> MagicMock:
    frames = _make_verified_frames(data)
    resp = MagicMock()
    resp.headers = httpx.Headers({"Content-Type": "application/vnd.filebridge.stream"})
    resp.request = MagicMock()
    resp.request.headers = httpx.Headers({"X-Signature": SIGNATURE})
    resp.iter_bytes = MagicMock(return_value=iter([frames]))
    resp.close = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# FileBridgeReadStream (plain, no token)
# ---------------------------------------------------------------------------


def test_read_stream_plain_all():
    resp = _make_plain_response([b"hello ", b"world"])
    stream = FileBridgeReadStream(resp)
    assert stream.read(-1) == b"hello world"


def test_read_stream_plain_partial():
    resp = _make_plain_response([b"hello world"])
    stream = FileBridgeReadStream(resp)
    assert stream.read(5) == b"hello"


def test_read_stream_plain_readinto():
    resp = _make_plain_response([b"hello world"])
    stream = FileBridgeReadStream(resp)
    buf = bytearray(5)
    n = stream.readinto(buf)
    assert n == 5
    assert bytes(buf) == b"hello"


def test_read_stream_multi_chunks():
    resp = _make_plain_response([b"chunk1", b"chunk2", b"chunk3"])
    stream = FileBridgeReadStream(resp)
    assert stream.read(-1) == b"chunk1chunk2chunk3"


# ---------------------------------------------------------------------------
# FileBridgeReadStream (verified / encrypted)
# ---------------------------------------------------------------------------


def test_read_stream_verified_roundtrip():
    original = b"verified stream data"
    resp = _make_verified_response(original)
    stream = FileBridgeReadStream(resp, token=TOKEN)
    assert stream.read(-1) == original


def test_read_stream_missing_sig():
    resp = MagicMock()
    resp.headers = httpx.Headers({"Content-Type": "application/vnd.filebridge.stream"})
    resp.request = MagicMock()
    resp.request.headers = httpx.Headers({})  # no X-Signature
    resp.iter_bytes = MagicMock(return_value=iter([]))
    with pytest.raises(FileBridgeError, match="Missing signature"):
        FileBridgeReadStream(resp, token=TOKEN)


def test_read_stream_unexpected_eof():
    """FileBridgeError when the stream ends before the STOP frame arrives."""
    aead = StreamAead(TOKEN, SIGNATURE)
    data_frame = encode_data(aead.encrypt(b"partial"))
    # No STOP frame — iterator exhausted after DATA
    resp = MagicMock()
    resp.headers = httpx.Headers({"Content-Type": "application/vnd.filebridge.stream"})
    resp.request = MagicMock()
    resp.request.headers = httpx.Headers({"X-Signature": SIGNATURE})
    resp.iter_bytes = MagicMock(return_value=iter([data_frame]))
    resp.close = MagicMock()

    stream = FileBridgeReadStream(resp, token=TOKEN)
    with pytest.raises(FileBridgeError):
        stream.read(-1)


# ---------------------------------------------------------------------------
# AsyncFileBridgeReadStream
# ---------------------------------------------------------------------------


def test_async_read_stream_plain():
    async def _coro():
        async def async_chunks():
            yield b"hello "
            yield b"world"

        resp = MagicMock()
        resp.headers = httpx.Headers({"Content-Type": "application/octet-stream"})
        resp.request = MagicMock()
        resp.request.headers = httpx.Headers({})
        resp.aiter_bytes = MagicMock(return_value=async_chunks())
        resp.aclose = AsyncMock()

        stream = AsyncFileBridgeReadStream(resp)
        result = await stream.read(-1)
        assert result == b"hello world"

    asyncio.run(_coro())


def test_async_read_stream_verified():
    async def _coro():
        original = b"async verified data"
        frames = _make_verified_frames(original)

        async def async_chunks():
            yield frames

        resp = MagicMock()
        resp.headers = httpx.Headers({"Content-Type": "application/vnd.filebridge.stream"})
        resp.request = MagicMock()
        resp.request.headers = httpx.Headers({"X-Signature": SIGNATURE})
        resp.aiter_bytes = MagicMock(return_value=async_chunks())
        resp.aclose = AsyncMock()

        stream = AsyncFileBridgeReadStream(resp, token=TOKEN)
        result = await stream.read(-1)
        assert result == original

    asyncio.run(_coro())


def test_async_read_stream_missing_sig():
    resp = MagicMock()
    resp.headers = httpx.Headers({"Content-Type": "application/vnd.filebridge.stream"})
    resp.request = MagicMock()
    resp.request.headers = httpx.Headers({})  # no X-Signature
    with pytest.raises(FileBridgeError, match="Missing signature"):
        AsyncFileBridgeReadStream(resp, token=TOKEN)
