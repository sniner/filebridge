from __future__ import annotations

import fnmatch
import io
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import PurePosixPath
from typing import IO, ContextManager, Literal, Type, overload

import httpx

from .core import (
    build_encrypted_write_body,
    decode_read_response,
    get_api_path,
    handle_response_errors,
    parse_json_response,
    prepare_encrypted_request_kwargs,
    prepare_request_kwargs,
)
from .exceptions import AuthenticationError, FileBridgeError, IsDirectoryError, NotFoundError
from .io import FileBridgeReadStream
from .models import ListResponse, Metadata

StrPath = str | PurePosixPath


class FilenameComparator(ABC):
    def __init__(self, base: str):
        self.base = self.normalize(str(base))

    @abstractmethod
    def normalize(self, name: str) -> str: ...

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.base == self.normalize(other)
        elif isinstance(other, self.__class__):
            return self.base == other.base
        return NotImplemented

    def match(self, name: str) -> bool:
        return fnmatch.fnmatchcase(self.normalize(name), self.base)

    def equals(self, name: str) -> bool:
        return self.base == self.normalize(str(name))

    @classmethod
    def compare(cls, a: str, b: str) -> bool:
        return cls(a).equals(b)

    @staticmethod
    def build(*, case_sensitive: bool) -> Type[FilenameComparator]:
        if case_sensitive:
            return CaseSensitiveComparator
        return CaseInsensitiveComparator


class CaseSensitiveComparator(FilenameComparator):
    def normalize(self, name: str) -> str:
        return name


class CaseInsensitiveComparator(FilenameComparator):
    def normalize(self, name: str) -> str:
        return name.casefold()


_WRITE_CHUNK = 64 * 1024


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


class LocationEntry:
    def __init__(
        self,
        loc: Location,
        path: LocationPath,
        metadata: Metadata | None = None,
    ):
        self._location = loc
        self._path = PurePosixPath(path)
        self._stat = metadata

    def __fspath__(self) -> str:
        return str(self.path)

    @property
    def path(self) -> PurePosixPath:
        return self._path

    def is_dir(self) -> bool:
        if self._stat is None:
            self.refresh()
        assert self._stat is not None
        return self._stat.is_dir

    def is_file(self) -> bool:
        return not self.is_dir()

    def refresh(self, *, extensive: bool | None = None) -> LocationEntry:
        ex = self._stat is not None and self._stat.sha256 is not None
        self._stat = self._location.stat(self, extensive=ex if extensive is None else extensive)
        return self

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def stem(self) -> str:
        return self._path.stem

    @property
    def suffix(self) -> str:
        return self._path.suffix

    @property
    def suffixes(self) -> list[str]:
        return self._path.suffixes

    @property
    def parent(self) -> PurePosixPath:
        return self._path.parent

    @property
    def location(self) -> Location:
        return self._location

    def is_relative_to(self, other: LocationPath) -> bool:
        if isinstance(other, LocationEntry):
            if self._location != other._location:
                return False
            other_path = other.path
        else:
            other_path = PurePosixPath(other)

        if self._location._case_sensitive:
            # pathlib.Path.is_relative_to() is always case-sensitive
            return self.path.is_relative_to(other_path)

        if len(self.path.parts) < len(other_path.parts):
            return False

        cmp = CaseInsensitiveComparator
        for t, o in zip(self.path.parts, other_path.parts):
            if not cmp.compare(t, o):
                return False
        return True

    def stat(self, *, extensive: bool | None = None, refresh: bool = False) -> Metadata:
        if self._stat is None:
            self.refresh(extensive=extensive)
        elif refresh or (extensive and self._stat.sha256 is None):
            self.refresh(extensive=extensive)
        assert self._stat is not None
        return self._stat

    def glob(self, pattern: str) -> Iterator[LocationEntry]:
        yield from self._location.glob(pattern, self)

    def iterdir(self) -> Iterator[LocationEntry]:
        if not self.is_dir():
            raise NotADirectoryError(f"{self._path} is not a directory")
        yield from self._location.iterdir(self)

    def walk(
        self,
    ) -> Iterator[tuple[PurePosixPath, list[LocationEntry], list[LocationEntry]]]:
        yield from self._location.walk(self)

    def __truediv__(self, other: LocationPath) -> LocationEntry:
        if isinstance(other, LocationEntry):
            if self._location != other._location:
                raise ValueError("Cannot join paths from different locations")
            other_path = other.path
        else:
            other_path = PurePosixPath(other)
        new_path = self._path / other_path
        return LocationEntry(self._location, new_path)

    @overload
    def open(
        self,
        mode: Literal["w", "wb"],
        *,
        encoding: str | None = ...,
    ) -> ContextManager[_WriteHandle]: ...

    @overload
    def open(
        self,
        mode: Literal["r", "rb"] = ...,
        *,
        encoding: None = ...,
        offset: int | None = ...,
        length: int | None = ...,
    ) -> ContextManager[FileBridgeReadStream]: ...

    @overload
    def open(
        self,
        mode: Literal["r", "rb"] = ...,
        *,
        encoding: str,
        offset: int | None = ...,
        length: int | None = ...,
    ) -> ContextManager[io.TextIOWrapper]: ...

    @contextmanager
    def open(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
        offset: int | None = None,
        length: int | None = None,
    ):
        with self._location.open(
            self._path,
            mode=mode,  # type: ignore[arg-type]
            encoding=encoding,  # type: ignore[arg-type]
            offset=offset,
            length=length,
        ) as f:
            yield f

    def __str__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(path={self.path!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LocationEntry):
            return NotImplemented
        if self._location != other._location:
            return False
        if self._location._case_sensitive:
            return self.path == other.path
        else:
            if len(self.path.parts) != len(other.path.parts):
                return False
            cmp = CaseInsensitiveComparator
            for t, o in zip(self.path.parts, other.path.parts):
                if not cmp.compare(t, o):
                    return False
        return True

    def __hash__(self) -> int:
        if self._location._case_sensitive:
            return hash((self._location, self._path))
        else:
            parts = tuple(p.casefold() for p in self._path.parts)
            return hash((self._location, parts))


LocationPath = StrPath | LocationEntry


class Location:
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

    def read(
        self,
        path: LocationPath,
        *,
        offset: int | None = None,
        length: int | None = None,
    ) -> bytes:
        str_path = str(path)
        if self.token:
            # Token mode: path in encrypted body
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                method="GET",
                url=url,
                token=self.token,
                path=str_path,
                offset=offset,
                length=length,
                extra_headers={"Accept": "application/vnd.filebridge.stream"},
            )
            response = self._send_request("GET", url, kwargs, req_nonce)
            return decode_read_response(
                self.token,
                response.headers.get("Content-Type", ""),
                response.content,
                response.request.headers.get("X-Signature"),
                str_path,
            )

        # No token: path in URL
        api_path = get_api_path(self.dir_id, str_path)
        params = {}
        if offset is not None:
            params["offset"] = offset
        if length is not None:
            params["length"] = length

        url = self._url(api_path)
        kwargs, req_nonce = prepare_request_kwargs(
            method="GET",
            url=url,
            token=self.token,
            kwargs={"params": params} if params else {},
        )
        headers = kwargs.setdefault("headers", {})
        headers["Accept"] = "application/octet-stream"

        response = self._send_request("GET", url, kwargs, req_nonce)

        return decode_read_response(
            self.token,
            response.headers.get("Content-Type", ""),
            response.content,
            response.request.headers.get("X-Signature"),
            str_path,
        )

    def write(
        self,
        path: LocationPath,
        data: bytes,
        *,
        offset: int | None = None,
    ):
        str_path = str(path)
        if self.token:
            # Token mode: path in META frame, not URL
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"headers": {"Content-Type": "application/vnd.filebridge.stream"}},
            )
            sig = kwargs.get("headers", {}).get("X-Signature", "")
            kwargs["content"] = build_encrypted_write_body(
                self.token,
                sig,
                data,
                path=str_path,
                offset=offset,
            )
            self._send_request("PUT", url, kwargs, req_nonce)
        else:
            api_path = get_api_path(self.dir_id, str_path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            url = self._url(api_path)
            kwargs, req_nonce = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"params": params, "headers": {"Content-Type": "application/octet-stream"}},
            )
            kwargs["content"] = data
            self._send_request("PUT", url, kwargs, req_nonce)

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
        str_path = str(path)
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                method="GET",
                url=url,
                token=self.token,
                path=str_path,
                offset=offset,
                length=length,
                extra_headers={"Accept": "application/vnd.filebridge.stream"},
            )
        else:
            api_path = get_api_path(self.dir_id, str_path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            if length is not None:
                params["length"] = length
            url = self._url(api_path)
            kwargs, req_nonce = prepare_request_kwargs(
                method="GET",
                url=url,
                token=self.token,
                kwargs={"params": params, "headers": {"Accept": "application/octet-stream"}},
            )
        kwargs.setdefault("headers", {})

        with self._client.client.stream("GET", url, **kwargs) as response:
            if not response.is_success:
                response.read()  # Ensure content is read before raising for error handling
                handle_response_errors(response.status_code, response.text)
                raise FileBridgeError(f"HTTP Error {response.status_code}: {response.text}")

            if self.token:
                resp_nonce = response.headers.get("X-Nonce")
                if resp_nonce != req_nonce:
                    raise AuthenticationError("Nonce mismatch")

            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type:
                body = response.read()
                sig = response.request.headers.get("X-Signature", "") if self.token else None
                data = parse_json_response(self.token, sig, body)
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
        str_path = str(path)

        def chunk_generator():
            if hasattr(stream, "read"):
                while True:
                    chunk = stream.read(64 * 1024)  # type: ignore[union-attr]
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
            from .core import build_encrypted_envelope
            from .stream import (
                StreamAead,
                encode_data,
                encode_meta,
                encode_stop,
            )

            # Token mode: path in META frame, not URL
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"headers": {"Content-Type": "application/vnd.filebridge.stream"}},
            )

            token = self.token
            assert token is not None

            def signed_chunk_generator():
                sig = kwargs.get("headers", {}).get("X-Signature", "")
                # Emit META frame first with encrypted envelope
                envelope = build_encrypted_envelope(token, sig, str_path, offset)
                yield encode_meta(envelope.encode())

                aead = StreamAead(token, sig)
                for chunk in chunk_generator():
                    encrypted_chunk = aead.encrypt(chunk)
                    yield encode_data(encrypted_chunk)
                yield encode_stop(aead.finalize())

            kwargs["content"] = signed_chunk_generator()
            self._send_request("PUT", url, kwargs, req_nonce)
        else:
            api_path = get_api_path(self.dir_id, str_path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            url = self._url(api_path)
            kwargs, req_nonce = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"params": params, "headers": {"Content-Type": "application/octet-stream"}},
            )
            kwargs["content"] = chunk_generator()
            self._send_request("PUT", url, kwargs, req_nonce)

    def list(
        self,
        path: LocationPath | None = None,
    ) -> Iterator[LocationEntry]:
        pure_path = PurePosixPath(path or "")
        str_path = str(pure_path)
        if self.token and str_path:
            # Token mode with subpath: path in encrypted body
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                "GET",
                url,
                self.token,
                str_path,
            )
            response = self._send_request("GET", url, kwargs, req_nonce)
        else:
            url = self._url(get_api_path(self.dir_id, str_path))
            kwargs, req_nonce = prepare_request_kwargs("GET", url, self.token, {})
            response = self._send_request("GET", url, kwargs, req_nonce)

        sig = response.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, response.content)
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
        pure_path = PurePosixPath(path)
        str_path = str(path)
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                "GET",
                url,
                self.token,
                str_path,
                extensive=extensive,
            )
        else:
            url = self._url(get_api_path(self.dir_id, str_path))
            params = {"extensive": "true"} if extensive else {}
            kwargs, req_nonce = prepare_request_kwargs(
                "GET", url, self.token, {"params": params} if params else {}
            )
        response = self._send_request("GET", url, kwargs, req_nonce)
        sig = response.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, response.content)
        if "items" in data:
            return Metadata(name=pure_path.name, is_dir=True, size=0, sha256=None)
        return Metadata(**data)

    def stat(
        self,
        path: LocationPath,
        *,
        extensive: bool = False,
    ) -> Metadata:
        return self.info(path, extensive=extensive)

    def exists(self, path: LocationPath) -> bool:
        try:
            self.info(path)
            return True
        except NotFoundError:
            return False

    def delete(self, path: LocationPath) -> None:
        str_path = str(path)
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = self._url(api_path)
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                "DELETE",
                url,
                self.token,
                str_path,
            )
        else:
            url = self._url(get_api_path(self.dir_id, str_path))
            kwargs, req_nonce = prepare_request_kwargs("DELETE", url, self.token, {})
        self._send_request("DELETE", url, kwargs, req_nonce)

    def iterdir(self, path: LocationPath | None = None) -> Iterator[LocationEntry]:
        yield from self.list(path)

    def glob(
        self,
        pattern: str,
        path: LocationPath | None = None,
        *,
        case_sensitive: bool | None = None,
    ) -> Iterator[LocationEntry]:
        parts = PurePosixPath(pattern).parts
        case_sense = self._case_sensitive if case_sensitive is None else case_sensitive

        return self._recursive_glob(
            str(PurePosixPath(path or "")),
            parts,
            CaseSensitiveComparator if case_sense else CaseInsensitiveComparator,
        )

    def _recursive_glob(
        self,
        current_path: str,
        pattern_parts: tuple[str, ...],
        comparator: Type[FilenameComparator],
        current_items: list[LocationEntry] | None = None,
    ) -> Iterator[LocationEntry]:
        if not pattern_parts:
            return

        pattern = pattern_parts[0]
        remaining = pattern_parts[1:]

        def get_items() -> list[LocationEntry]:
            if current_items is not None:
                return current_items
            return list(self.list(current_path))

        # Special case: recursive wildcard **
        if pattern == "**":
            items = get_items()

            # 1. Apply remaining pattern at current directory (zero depth)
            if remaining:
                yield from self._recursive_glob(current_path, remaining, comparator, items)
            else:
                # Bare ** without remainder: list everything recursively
                yield from self._walk_all(current_path, items)
                return

            # 2. Recurse into subdirectories and continue ** there
            for item in items:
                if item.is_dir():
                    yield from self._recursive_glob(str(item.path), pattern_parts, comparator)
            return

        cmp = comparator(pattern)

        for item in get_items():
            if cmp.match(item.name):
                if not remaining:
                    # End of pattern reached
                    yield item
                elif item.is_dir():
                    # Recurse with remaining pattern parts
                    yield from self._recursive_glob(str(item.path), remaining, comparator)

    def _walk_all(
        self,
        path: str,
        current_items: list[LocationEntry] | None = None,
    ) -> Iterator[LocationEntry]:
        """Helper for bare ** pattern: yield all entries recursively."""
        items = current_items if current_items is not None else self.list(path)
        for item in items:
            yield item
            if item.is_dir():
                yield from self._walk_all(str(item.path))

    def walk(
        self,
        path: LocationPath | None = None,
    ) -> Iterator[tuple[PurePosixPath, list[LocationEntry], list[LocationEntry]]]:
        p = PurePosixPath(path or "")
        all_items = list(self.list(p))
        subdirs = [m for m in all_items if m.is_dir()]
        files = [m for m in all_items if not m.is_dir()]
        yield (p, subdirs, files)
        for sub in subdirs:
            yield from self.walk(p / sub.name)

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


class FileBridgeClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.client = httpx.Client()

    def location(
        self,
        dir_id: str,
        token: str | None = None,
        *,
        case_sensitive: bool = True,
    ) -> Location:
        return Location(self, dir_id, token, case_sensitive=case_sensitive)

    at = location

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
