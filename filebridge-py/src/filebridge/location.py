"""Location — a shared directory on a Filebridge server."""

from __future__ import annotations

import io
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import PurePosixPath
from typing import IO, TYPE_CHECKING, ContextManager, Literal, overload

import httpx

from .core import (
    get_api_path,
    handle_response_errors,
    prepare_encrypted_request_kwargs,
    prepare_request_kwargs,
)
from .stream import (
    CHUNK_SIZE,
    StreamAead,
    build_encrypted_envelope,
    build_encrypted_write_body,
    decode_read_response,
    encode_data,
    encode_meta,
    encode_stop,
    parse_json_response,
)
from .entry import LocationEntry, LocationPath
from .exceptions import AuthenticationError, FileBridgeError, IsDirectoryError, NotFoundError
from .traverse import glob_entries, walk_entries
from .io import FileBridgeReadStream
from .models import ListResponse, Metadata

if TYPE_CHECKING:
    from .client import FileBridgeClient


_WRITE_CHUNK = CHUNK_SIZE


class _WriteHandle:
    """Buffering writable file-like handle. Flushes in chunks via Location.write()."""

    def __init__(
        self,
        loc: Location,
        path: str,
        *,
        encoding: str | None = None,
    ):
        self._loc = loc
        self._path = path
        self._encoding = encoding
        self._buffer = bytearray()
        self._offset = 0
        self._closed = False

    def write(self, data: bytes | str) -> int:
        if self._closed:
            raise ValueError("write to closed file")
        if isinstance(data, str):
            data = data.encode(self._encoding or "utf-8")
        n = len(data)
        self._buffer.extend(data)
        while len(self._buffer) >= _WRITE_CHUNK:
            chunk = bytes(self._buffer[:_WRITE_CHUNK])
            self._loc.write(self._path, chunk, offset=self._offset)
            self._offset += len(chunk)
            del self._buffer[:_WRITE_CHUNK]
        return n

    def flush(self):
        if self._closed:
            raise ValueError("flush of closed file")
        if self._buffer:
            self._loc.write(self._path, bytes(self._buffer), offset=self._offset)
            self._offset += len(self._buffer)
            self._buffer.clear()

    def close(self):
        if not self._closed:
            self.flush()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self._closed = True
        else:
            self.close()


class Location:
    """A shared directory on a Filebridge server.

    Provides methods for reading, writing, listing, and deleting files.
    Obtained via ``FileBridgeClient.location()``.

    When *token* is set, all requests are HMAC-signed and file content is
    encrypted with ChaCha20-Poly1305.

    Args:
        client: The parent client.
        dir_id: Server-side directory identifier.
        token: Optional authentication token for HMAC signing and encryption.
        case_sensitive: Whether filename comparisons are case-sensitive
            (affects ``glob()`` and ``LocationEntry`` equality).
    """

    def __init__(
        self,
        client: FileBridgeClient,
        dir_id: str,
        token: str | None = None,
        *,
        case_sensitive: bool = True,
    ):
        self.dir_id = dir_id
        self._token = token
        self._client = client
        self._case_sensitive = case_sensitive
        self._root: LocationEntry | None = None

    @property
    def case_sensitive(self) -> bool:
        return self._case_sensitive

    @property
    def token(self) -> str | None:
        return self._token

    def _url(self, api_path: str) -> str:
        """Build a full URL from an API path."""
        return self._client.base_url + api_path

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return (
            self.dir_id == other.dir_id
            and self._token == other._token
            and self._client.base_url == other._client.base_url
        )

    def __hash__(self) -> int:
        return hash((self.dir_id, self._token, self._client.base_url))

    def __repr__(self) -> str:
        return f"Location(dir_id={self.dir_id!r}, base_url={self._client.base_url!r})"

    @property
    def root(self) -> LocationEntry:
        if self._root is None:
            self._root = LocationEntry(
                self,
                PurePosixPath("/"),
                Metadata(name="/", is_dir=True),
            )
        return self._root

    def _send_request(
        self,
        method: str,
        url: str,
        kwargs: dict,
        req_nonce: str | None = None,
    ) -> httpx.Response:
        response = self._client.client.request(method, url, **kwargs)
        if not response.is_success:
            handle_response_errors(response.status_code, response.text)
            raise FileBridgeError(f"HTTP Error {response.status_code}: {response.text}")

        if self.token:
            resp_nonce = response.headers.get("X-Nonce")
            if resp_nonce != req_nonce:
                raise AuthenticationError("Nonce mismatch")
        return response

    def _prepare_request(
        self,
        method: str,
        path: str,
        *,
        offset: int | None = None,
        length: int | None = None,
        extensive: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[str, dict, str]:
        """Build URL, kwargs, and nonce for a request.

        Handles the token/plain branching: in token mode the path and
        parameters go into an encrypted envelope; otherwise they are
        placed in the URL and query string.
        """
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, nonce = prepare_encrypted_request_kwargs(
                method,
                url,
                self.token,
                path,
                offset=offset,
                length=length,
                extra_headers=extra_headers,
                extensive=extensive,
            )
        else:
            api_path = get_api_path(self.dir_id, path)
            url = self._url(api_path)
            params: dict[str, object] = {}
            if offset is not None:
                params["offset"] = offset
            if length is not None:
                params["length"] = length
            if extensive:
                params["extensive"] = "true"
            init_kwargs: dict[str, object] = {}
            if params:
                init_kwargs["params"] = params
            kwargs, nonce = prepare_request_kwargs(method, url, self.token, init_kwargs)
            if extra_headers:
                kwargs.setdefault("headers", {}).update(extra_headers)
        return url, kwargs, nonce

    def _prepare_write_request(self, path: str) -> tuple[str, dict, str]:
        """Build URL, kwargs, and nonce for a token-mode write (stream frames)."""
        api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
        url = self._url(api_path)
        kwargs, nonce = prepare_request_kwargs(
            "PUT", url, self.token,
            {"headers": {"Content-Type": "application/vnd.filebridge.stream"}},
        )
        return url, kwargs, nonce

    def _response_sig(self, response: httpx.Response) -> str | None:
        """Return the request signature when in token mode, else ``None``."""
        if self.token:
            return response.request.headers.get("X-Signature", "")
        return None

    def read(
        self,
        path: LocationPath,
        *,
        offset: int | None = None,
        length: int | None = None,
    ) -> bytes:
        """Read the entire file (or a byte range) and return its contents."""
        str_path = str(path)
        accept = "application/vnd.filebridge.stream" if self.token else "application/octet-stream"
        url, kwargs, nonce = self._prepare_request(
            "GET", str_path, offset=offset, length=length,
            extra_headers={"Accept": accept},
        )
        response = self._send_request("GET", url, kwargs, nonce)
        return decode_read_response(
            self.token,
            response.headers.get("Content-Type", ""),
            response.content,
            self._response_sig(response),
            str_path,
        )

    def write(
        self,
        path: LocationPath,
        data: bytes,
        *,
        offset: int | None = None,
    ):
        """Write *data* to the file at *path*, optionally at *offset*."""
        str_path = str(path)
        if self.token:
            # Token mode: path in META frame, body is encrypted stream frames
            url, kwargs, nonce = self._prepare_write_request(str_path)
            sig = kwargs.get("headers", {}).get("X-Signature", "")
            kwargs["content"] = build_encrypted_write_body(
                self.token, sig, data, path=str_path, offset=offset,
            )
            self._send_request("PUT", url, kwargs, nonce)
        else:
            url, kwargs, nonce = self._prepare_request(
                "PUT", str_path, offset=offset,
                extra_headers={"Content-Type": "application/octet-stream"},
            )
            kwargs["content"] = data
            self._send_request("PUT", url, kwargs, nonce)

    @overload
    def read_stream(
        self,
        path: LocationPath,
        *,
        offset: int | None = ...,
        length: int | None = ...,
        encoding: None = None,
    ) -> ContextManager[FileBridgeReadStream]: ...

    @overload
    def read_stream(
        self,
        path: LocationPath,
        *,
        offset: int | None = ...,
        length: int | None = ...,
        encoding: str,
    ) -> ContextManager[io.TextIOWrapper]: ...

    @contextmanager
    def read_stream(
        self,
        path: LocationPath,
        *,
        offset: int | None = None,
        length: int | None = None,
        encoding: str | None = None,
    ):
        """Stream file content as a context manager.

        Yields a ``FileBridgeReadStream`` (raw bytes) or a ``TextIOWrapper``
        when *encoding* is specified.
        """
        str_path = str(path)
        accept = "application/vnd.filebridge.stream" if self.token else "application/octet-stream"
        url, kwargs, nonce = self._prepare_request(
            "GET", str_path, offset=offset, length=length,
            extra_headers={"Accept": accept},
        )

        with self._client.client.stream("GET", url, **kwargs) as response:
            if not response.is_success:
                response.read()
                handle_response_errors(response.status_code, response.text)
                raise FileBridgeError(f"HTTP Error {response.status_code}: {response.text}")

            if self.token:
                resp_nonce = response.headers.get("X-Nonce")
                if resp_nonce != nonce:
                    raise AuthenticationError("Nonce mismatch")

            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                body = response.read()
                data = parse_json_response(self.token, self._response_sig(response), body)
                if "items" in data:
                    raise IsDirectoryError(f"{str_path} is a directory")

            raw_stream = FileBridgeReadStream(response, self.token)
            if encoding:
                wrapper = io.TextIOWrapper(raw_stream, encoding=encoding)
                try:
                    yield wrapper
                finally:
                    wrapper.close()
            else:
                try:
                    yield raw_stream
                finally:
                    raw_stream.close()

    stream_read = read_stream

    def write_stream(
        self,
        path: LocationPath,
        stream: io.RawIOBase | IO[bytes] | Iterable[bytes | str],
        *,
        offset: int | None = None,
    ):
        """Write file content from a readable stream or iterable of chunks."""
        str_path = str(path)

        def chunk_generator():
            if hasattr(stream, "read"):
                while True:
                    chunk = stream.read(CHUNK_SIZE)  # type: ignore[union-attr]
                    if not chunk:
                        break
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    yield chunk
            else:
                for chunk in stream:
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    yield chunk

        if self.token:
            url, kwargs, nonce = self._prepare_write_request(str_path)
            token = self.token

            def signed_chunk_generator():
                sig = kwargs.get("headers", {}).get("X-Signature", "")
                envelope = build_encrypted_envelope(token, sig, str_path, offset)
                yield encode_meta(envelope.encode())

                aead = StreamAead(token, sig)
                for chunk in chunk_generator():
                    yield encode_data(aead.encrypt(chunk))
                yield encode_stop(aead.finalize())

            kwargs["content"] = signed_chunk_generator()
            self._send_request("PUT", url, kwargs, nonce)
        else:
            url, kwargs, nonce = self._prepare_request(
                "PUT", str_path, offset=offset,
                extra_headers={"Content-Type": "application/octet-stream"},
            )
            kwargs["content"] = chunk_generator()
            self._send_request("PUT", url, kwargs, nonce)

    def list(
        self,
        path: LocationPath | None = None,
        *,
        extensive: bool = False,
    ) -> Iterator[LocationEntry]:
        """List entries in a directory. Pass ``None`` for the root directory."""
        pure_path = PurePosixPath(path or "")
        str_path = str(pure_path)
        if str_path == ".":
            str_path = ""
        url, kwargs, nonce = self._prepare_request("GET", str_path, extensive=extensive)
        response = self._send_request("GET", url, kwargs, nonce)
        data = parse_json_response(self.token, self._response_sig(response), response.content)
        if "items" in data:
            list_resp = ListResponse(**data)
            for meta in list_resp.items:
                yield LocationEntry(loc=self, path=pure_path / meta.name, metadata=meta)
        else:
            meta = Metadata(**data)
            entry_path = pure_path if pure_path.name == meta.name else pure_path / meta.name
            yield LocationEntry(loc=self, path=entry_path, metadata=meta)

    def info(
        self,
        path: LocationPath,
        *,
        extensive: bool = False,
    ) -> Metadata:
        """Return metadata for the file or directory at *path*.

        Args:
            extensive: Also request the SHA-256 hash of the file content.
        """
        pure_path = PurePosixPath(path)
        str_path = str(path)
        url, kwargs, nonce = self._prepare_request("GET", str_path, extensive=extensive)
        response = self._send_request("GET", url, kwargs, nonce)
        data = parse_json_response(self.token, self._response_sig(response), response.content)
        if "items" in data:
            return Metadata(name=pure_path.name, is_dir=True, size=0, sha256=None)
        return Metadata(**data)

    def stat(
        self,
        path: LocationPath,
        *,
        extensive: bool = False,
    ) -> Metadata:
        """Alias for ``info()``."""
        return self.info(path, extensive=extensive)

    def exists(self, path: LocationPath) -> bool:
        """Return ``True`` if *path* exists on the server."""
        try:
            self.info(path)
            return True
        except NotFoundError:
            return False

    def delete(self, path: LocationPath) -> None:
        """Delete the file at *path*."""
        url, kwargs, nonce = self._prepare_request("DELETE", str(path))
        self._send_request("DELETE", url, kwargs, nonce)

    def iterdir(
        self, path: LocationPath | None = None, *, extensive: bool = False
    ) -> Iterator[LocationEntry]:
        """Iterate over entries in a directory. Alias for ``list()``."""
        yield from self.list(path, extensive=extensive)

    def glob(
        self,
        pattern: str,
        path: LocationPath | None = None,
        *,
        case_sensitive: bool | None = None,
        extensive: bool = False,
    ) -> Iterator[LocationEntry]:
        """Iterate over entries matching a glob *pattern*.

        Supports ``*``, ``?``, ``[seq]``, and recursive ``**`` patterns.
        """
        case_sense = self._case_sensitive if case_sensitive is None else case_sensitive
        str_path = str(path) if path is not None else None
        return glob_entries(self, pattern, str_path, case_sensitive=case_sense, extensive=extensive)

    def walk(
        self,
        path: LocationPath | None = None,
        *,
        extensive: bool = False,
    ) -> Iterator[tuple[PurePosixPath, list[LocationEntry], list[LocationEntry]]]:
        """Walk the directory tree, yielding ``(dirpath, subdirs, files)`` tuples.

        Similar to ``os.walk()``.
        """
        str_path = str(path) if path is not None else None
        return walk_entries(self, str_path, extensive=extensive)

    @overload
    def open(
        self,
        path: LocationPath,
        mode: Literal["w", "wb"],
        *,
        encoding: str | None = ...,
    ) -> ContextManager[_WriteHandle]: ...

    @overload
    def open(
        self,
        path: LocationPath,
        mode: Literal["r", "rb"] = ...,
        *,
        encoding: None = ...,
        offset: int | None = ...,
        length: int | None = ...,
    ) -> ContextManager[FileBridgeReadStream]: ...

    @overload
    def open(
        self,
        path: LocationPath,
        mode: Literal["r", "rb"] = ...,
        *,
        encoding: str,
        offset: int | None = ...,
        length: int | None = ...,
    ) -> ContextManager[io.TextIOWrapper]: ...

    @contextmanager
    def open(
        self,
        path: LocationPath,
        mode: str = "r",
        *,
        encoding: str | None = None,
        offset: int | None = None,
        length: int | None = None,
    ):
        """Open a file for reading or writing as a context manager.

        Args:
            path: File path within the location.
            mode: ``"r"``/``"rb"`` for reading, ``"w"``/``"wb"`` for writing.
            encoding: Text encoding. When set in read mode, yields a
                ``TextIOWrapper``; in write mode, encodes strings before sending.
            offset: Start reading at this byte offset (read mode only).
            length: Read at most this many bytes (read mode only).
        """
        str_path = str(path)
        if "w" in mode:
            with _WriteHandle(self, str_path, encoding=encoding) as handle:
                yield handle
        elif "r" in mode:
            with self.read_stream(
                str_path,
                offset=offset,
                length=length,
                encoding=encoding,
            ) as stream:
                yield stream
        else:
            raise ValueError(f"Unsupported mode: {mode!r}; use 'r' or 'w'")
