"""Location — a shared directory on a Filebridge server."""

from __future__ import annotations

import io
import json
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
    Reply,
    StreamAead,
    StreamError,
    build_encrypted_envelope,
    build_encrypted_write_body,
    decode_verified_stream_content,
    encode_data,
    encode_meta,
    encode_stop,
    open_reply,
)
from .entry import LocationEntry, LocationPath
from .exceptions import (
    AuthenticationError,
    FileBridgeError,
    IsDirectoryError,
    NotFoundError,
    UnverifiedResponseError,
)
from .traverse import glob_entries, walk_entries
from .io import FileBridgeReadStream
from .models import ListResponse, Metadata, Permissions

if TYPE_CHECKING:
    from .client import FileBridgeClient


_WRITE_CHUNK = CHUNK_SIZE

_STREAM_TYPE = "application/vnd.filebridge.stream"

_EXCERPT_LEN = 200
"""Longest part of an unverified response body that is put into an error."""


def _excerpt(text: str) -> str:
    """The start of an unverified response body, for an error message.

    Anybody on the path can have written this text and it may end up on a
    terminal, so control characters are replaced.
    """
    text = "".join(c if c.isprintable() else " " for c in text.strip())
    if len(text) > _EXCERPT_LEN:
        return text[:_EXCERPT_LEN] + "..."
    return text


MAX_REPLY_SIZE = 64 * 1024 * 1024
"""Largest response body that is read when it is not file content.

Metadata, a directory listing, an acknowledgement and an error are read into
memory as a whole. In token mode nothing of such a body is verified before it
is complete, so its size needs a limit that does not come from the sender.
"""


def _too_large() -> str:
    return f"response larger than {MAX_REPLY_SIZE // (1024 * 1024)} MiB"


def _read_limited(response: httpx.Response) -> bytes | None:
    """Read the body of a response that is not file content.

    Returns ``None`` for a body larger than ``MAX_REPLY_SIZE``. The rest of it
    is not read.
    """
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > MAX_REPLY_SIZE:
            return None
    return bytes(body)


def _read_plain(response: httpx.Response) -> bytes:
    """Read the body of a response of a location without a token.

    Raises for an error status and for a body larger than ``MAX_REPLY_SIZE``.
    Not for file content, which has no limit.
    """
    body = _read_limited(response)
    if body is None:
        raise FileBridgeError(f"HTTP {response.status_code}: {_too_large()}")
    if not response.is_success:
        text = body.decode("utf-8", errors="replace")
        handle_response_errors(response.status_code, text)
        raise FileBridgeError(f"HTTP Error {response.status_code}: {text}")
    return body


def _is_json(response: httpx.Response) -> bool:
    return "application/json" in response.headers.get("Content-Type", "")


def _not_file_content(data: object, path: str) -> FileBridgeError:
    """The error for a read that was answered with JSON instead of content."""
    if isinstance(data, dict) and "items" in data:
        return IsDirectoryError(f"{path} is a directory")
    return FileBridgeError("Unexpected JSON metadata instead of file content")


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
        self._started = False
        self._closed = False

    def _send(self, data: bytes):
        # The first write must omit the offset: the server only truncates an
        # existing file when no offset is given, so writing at offset 0 would
        # leave the tail of a longer pre-existing file in place.
        self._loc.write(self._path, data, offset=self._offset if self._started else None)
        self._started = True
        self._offset += len(data)

    def write(self, data: bytes | str) -> int:
        if self._closed:
            raise ValueError("write to closed file")
        if isinstance(data, str):
            data = data.encode(self._encoding or "utf-8")
        n = len(data)
        self._buffer.extend(data)
        while len(self._buffer) >= _WRITE_CHUNK:
            self._send(bytes(self._buffer[:_WRITE_CHUNK]))
            del self._buffer[:_WRITE_CHUNK]
        return n

    def flush(self):
        if self._closed:
            raise ValueError("flush of closed file")
        if self._buffer:
            self._send(bytes(self._buffer))
            self._buffer.clear()

    def close(self):
        if not self._closed:
            self.flush()
            if not self._started:
                # Nothing was written: still create/truncate the file,
                # matching the semantics of opening a local file with "w".
                self._send(b"")
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
    ) -> Reply:
        """Send a request and return the server's reply.

        With a token, the reply is the decrypted and verified response.
        Without one, it is the status and the JSON body, if there is one, of
        the plain response.
        """
        # Opened as a stream, so that the body is read here: with a limit, and
        # not at all if it is a file stream.
        with self._client.client.stream(method, url, **kwargs) as response:
            if self.token:
                return self._open_reply(response, req_nonce)

            content = _read_plain(response)
            body = json.loads(content) if content and _is_json(response) else None
            return Reply(status=response.status_code, body=body)

    def _request_json(
        self,
        method: str,
        url: str,
        kwargs: dict,
        req_nonce: str | None = None,
    ) -> dict:
        """Send a request and return the JSON result of the server's reply."""
        body = self._send_request(method, url, kwargs, req_nonce).body
        if not isinstance(body, dict):
            raise FileBridgeError("Missing result in response")
        return body

    def _is_encrypted_stream(self, response: httpx.Response) -> bool:
        return response.is_success and _STREAM_TYPE in response.headers.get("Content-Type", "")

    def _check_nonce(self, response: httpx.Response, req_nonce: str | None) -> None:
        if response.headers.get("X-Nonce") != req_nonce:
            raise AuthenticationError("Nonce mismatch")

    def _open_reply(self, response: httpx.Response, req_nonce: str | None) -> Reply:
        """Decrypt and verify the response of a location with a token.

        Returns only a reply with a success status that the server provably
        sent in answer to this request. A reply with an error status raises
        the exception for that status, anything that is not an encrypted reply
        raises ``UnverifiedResponseError``.

        Reads the body of the response, up to ``MAX_REPLY_SIZE``. The body of
        a file stream is not read.
        """
        assert self.token is not None
        unverified = f"unverified response from server: {response.status_code}"
        if self._is_encrypted_stream(response):
            # Nothing of a stream is verified before its frames are decrypted,
            # and its body is file content, not text for a message.
            raise UnverifiedResponseError(
                f"{unverified} file stream in place of an encrypted response"
            )
        body = _read_limited(response)
        if body is None:
            raise UnverifiedResponseError(f"{unverified} {_too_large()}")
        try:
            reply = open_reply(self.token, self._response_sig(response) or "", body)
        except StreamError:
            text = body.decode("utf-8", errors="replace")
            raise UnverifiedResponseError(f"{unverified} {_excerpt(text)}") from None
        self._check_nonce(response, req_nonce)
        # Only a success status counts as one. The server sends no other
        # status below 400.
        if not 200 <= reply.status < 300:
            message = reply.error or ""
            handle_response_errors(reply.status, message)
            raise FileBridgeError(f"HTTP Error {reply.status}: {message}")
        return reply

    def _prepare_request(
        self,
        method: str,
        path: str,
        *,
        offset: int | None = None,
        length: int | None = None,
        extensive: bool = False,
        extra_headers: dict[str, str] | None = None,
        target: str | None = None,
        content: bool = False,
    ) -> tuple[str, dict, str]:
        """Build URL, kwargs, and nonce for a request.

        Handles the token/plain branching: in token mode the path and
        parameters go into an encrypted envelope; otherwise they are
        placed in the URL and query string.

        With *content*, a GET asks for the content of the file instead of its
        metadata: in the envelope in token mode, where no header is signed,
        and in the ``Accept`` header otherwise.
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
                target=target,
                content=content,
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
            if target is not None:
                params["target"] = target.lstrip("/")
            init_kwargs: dict[str, object] = {}
            if params:
                init_kwargs["params"] = params
            kwargs, nonce = prepare_request_kwargs(method, url, self.token, init_kwargs)
            if content:
                kwargs.setdefault("headers", {})["Accept"] = "application/octet-stream"
            if extra_headers:
                kwargs.setdefault("headers", {}).update(extra_headers)
        return url, kwargs, nonce

    def _prepare_write_request(self, path: str) -> tuple[str, dict, str]:
        """Build URL, kwargs, and nonce for a token-mode write (stream frames)."""
        api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
        url = self._url(api_path)
        kwargs, nonce = prepare_request_kwargs(
            "PUT",
            url,
            self.token,
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
        url, kwargs, nonce = self._prepare_request(
            "GET",
            str_path,
            offset=offset,
            length=length,
            content=True,
        )
        response = self._client.client.request("GET", url, **kwargs)
        if self.token:
            if not self._is_encrypted_stream(response):
                raise _not_file_content(self._open_reply(response, nonce).body, str_path)
            self._check_nonce(response, nonce)
            return decode_verified_stream_content(
                self.token, self._response_sig(response) or "", response.content
            )

        if not response.is_success or _is_json(response):
            raise _not_file_content(json.loads(_read_plain(response)), str_path)
        return response.content

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
                self.token,
                sig,
                data,
                path=str_path,
                offset=offset,
            )
            self._send_request("PUT", url, kwargs, nonce)
        else:
            url, kwargs, nonce = self._prepare_request(
                "PUT",
                str_path,
                offset=offset,
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
        url, kwargs, nonce = self._prepare_request(
            "GET",
            str_path,
            offset=offset,
            length=length,
            content=True,
        )

        with self._client.client.stream("GET", url, **kwargs) as response:
            if self.token:
                if not self._is_encrypted_stream(response):
                    raise _not_file_content(self._open_reply(response, nonce).body, str_path)
                self._check_nonce(response, nonce)
            elif not response.is_success or _is_json(response):
                raise _not_file_content(json.loads(_read_plain(response)), str_path)

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
                "PUT",
                str_path,
                offset=offset,
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
        data = self._request_json("GET", url, kwargs, nonce)
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
        data = self._request_json("GET", url, kwargs, nonce)
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

    def permissions(self) -> Permissions:
        """Return the permissions the server grants for this location.

        Issues an HTTP ``OPTIONS`` request against the location root and
        decodes the server's permission set. The values are advisory: the
        server remains the source of truth, but clients can use them to
        short-circuit operations that aren't allowed.
        """
        api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
        url = self._url(api_path)
        kwargs, nonce = prepare_request_kwargs("OPTIONS", url, self.token, {})
        data = self._request_json("OPTIONS", url, kwargs, nonce)
        perms = data.get("permissions")
        if perms is None:
            raise FileBridgeError("Missing 'permissions' field in response")
        return Permissions(**perms)

    def delete(self, path: LocationPath) -> None:
        """Delete the file at *path*."""
        url, kwargs, nonce = self._prepare_request("DELETE", str(path))
        self._send_request("DELETE", url, kwargs, nonce)

    def rename(self, src: LocationPath, dst: LocationPath) -> None:
        """Rename (move) the file at *src* to *dst* within this location.

        Both paths are relative to the location root; moving across locations
        is not supported. Only regular files can be renamed — the server
        rejects directories.

        An existing *dst* is replaced, which the location must permit via
        ``allow_replace``. The operation itself needs ``allow_create`` and
        ``allow_delete``.
        """
        url, kwargs, nonce = self._prepare_request("POST", str(src), target=str(dst))
        self._send_request("POST", url, kwargs, nonce)

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
        return glob_entries(
            self, pattern, str_path, case_sensitive=case_sense, extensive=extensive
        )

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
