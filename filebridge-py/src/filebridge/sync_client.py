from __future__ import annotations

import fnmatch
import io
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import PurePosixPath
from typing import ContextManager, List, Optional, overload

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


_WRITE_CHUNK = 64 * 1024


class _WriteHandle:
    """Buffering writable file-like handle. Flushes in chunks via Location.write()."""

    def __init__(self, loc: "Location", path: str, encoding: Optional[str] = None):
        self._loc = loc
        self._path = path
        self._encoding = encoding
        self._buffer = b""
        self._offset = 0
        self._closed = False

    def write(self, data: bytes | str) -> int:
        if self._closed:
            raise ValueError("write to closed file")
        if isinstance(data, str):
            data = data.encode(self._encoding or "utf-8")
        n = len(data)
        self._buffer += data
        while len(self._buffer) >= _WRITE_CHUNK:
            chunk = self._buffer[:_WRITE_CHUNK]
            self._loc.write(self._path, chunk, offset=self._offset)
            self._offset += len(chunk)
            self._buffer = self._buffer[_WRITE_CHUNK:]
        return n

    def flush(self):
        if self._closed:
            raise ValueError("flush of closed file")
        if self._buffer:
            self._loc.write(self._path, self._buffer, offset=self._offset)
            self._offset += len(self._buffer)
            self._buffer = b""

    def close(self):
        if not self._closed:
            self.flush()
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class Location:
    def __init__(
        self,
        client: "FileBridgeClient",
        dir_id: str,
        token: Optional[str] = None,
    ):
        self.dir_id = dir_id
        self.token = token
        self.http_client = client.client
        self._client = client

    def _send_request(
        self, method: str, url: str, kwargs: dict, req_nonce: Optional[str] = None
    ) -> httpx.Response:
        response = self.http_client.request(method, url, **kwargs)
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
        path: StrPath,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> bytes:
        path = str(PurePosixPath(path))
        if self.token:
            # Token mode: path in encrypted body
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                method="GET",
                url=url,
                token=self.token,
                path=path,
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
                path,
            )

        # No token: path in URL
        api_path = get_api_path(self.dir_id, path)
        params = {}
        if offset is not None:
            params["offset"] = offset
        if length is not None:
            params["length"] = length

        url = f"{self._client.base_url.rstrip('/')}/{api_path}"
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
            path,
        )

    def write(self, path: StrPath, data: bytes, offset: Optional[int] = None):
        path = str(PurePosixPath(path))
        if self.token:
            # Token mode: path in META frame, not URL
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
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
                path=path,
                offset=offset,
            )
            self._send_request("PUT", url, kwargs, req_nonce)
        else:
            api_path = get_api_path(self.dir_id, path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
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
        path: StrPath,
        offset: Optional[int] = ...,
        length: Optional[int] = ...,
        encoding: None = None,
    ) -> ContextManager[FileBridgeReadStream]: ...

    @overload
    def read_stream(
        self,
        path: StrPath,
        offset: Optional[int] = ...,
        length: Optional[int] = ...,
        *,
        encoding: str,
    ) -> ContextManager[io.TextIOWrapper]: ...

    @contextmanager
    def read_stream(
        self,
        path: StrPath,
        offset: Optional[int] = None,
        length: Optional[int] = None,
        encoding: Optional[str] = None,
    ):
        path = str(PurePosixPath(path))
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                method="GET",
                url=url,
                token=self.token,
                path=path,
                offset=offset,
                length=length,
                extra_headers={"Accept": "application/vnd.filebridge.stream"},
            )
        else:
            api_path = get_api_path(self.dir_id, path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            if length is not None:
                params["length"] = length
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_request_kwargs(
                method="GET",
                url=url,
                token=self.token,
                kwargs={"params": params, "headers": {"Accept": "application/octet-stream"}},
            )
        kwargs.setdefault("headers", {})

        with self.http_client.stream("GET", url, **kwargs) as response:
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
                    raise IsDirectoryError(f"{path} is a directory")

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

    def write_stream(self, path: StrPath, stream, offset: Optional[int] = None):
        path = str(PurePosixPath(path))

        def chunk_generator():
            if hasattr(stream, "read"):
                while True:
                    chunk = stream.read(64 * 1024)
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
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
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
                envelope = build_encrypted_envelope(token, sig, path, offset)
                yield encode_meta(envelope.encode())

                aead = StreamAead(token, sig)
                for chunk in chunk_generator():
                    encrypted_chunk = aead.encrypt(chunk)
                    yield encode_data(encrypted_chunk)
                yield encode_stop(aead.finalize())

            kwargs["content"] = signed_chunk_generator()
            self._send_request("PUT", url, kwargs, req_nonce)
        else:
            api_path = get_api_path(self.dir_id, path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"params": params, "headers": {"Content-Type": "application/octet-stream"}},
            )
            kwargs["content"] = chunk_generator()
            self._send_request("PUT", url, kwargs, req_nonce)

    def list(self, path: StrPath | None = None) -> List[Metadata]:
        path = str(PurePosixPath(path)) if path is not None else None
        if self.token and path:
            # Token mode with subpath: path in encrypted body
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                "GET",
                url,
                self.token,
                path,
            )
            response = self._send_request("GET", url, kwargs, req_nonce)
        else:
            url = f"{self._client.base_url.rstrip('/')}/{get_api_path(self.dir_id, path)}"
            kwargs, req_nonce = prepare_request_kwargs("GET", url, self.token, {})
            response = self._send_request("GET", url, kwargs, req_nonce)

        sig = response.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, response.content)
        if "items" not in data:
            meta = Metadata(**data)
            return [meta]

        list_resp = ListResponse(**data)
        return list_resp.items

    def info(self, path: StrPath, extensive: bool = False) -> Metadata:
        path = str(PurePosixPath(path))
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                "GET",
                url,
                self.token,
                path,
                extensive=extensive,
            )
        else:
            url = f"{self._client.base_url.rstrip('/')}/{get_api_path(self.dir_id, path)}"
            params = {"extensive": "true"} if extensive else {}
            kwargs, req_nonce = prepare_request_kwargs(
                "GET", url, self.token, {"params": params} if params else {}
            )
        response = self._send_request("GET", url, kwargs, req_nonce)
        sig = response.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, response.content)
        return Metadata(**data)

    def stat(self, path: StrPath, extensive: bool = False) -> Metadata:
        return self.info(path, extensive=extensive)

    def exists(self, path: StrPath) -> bool:
        path = str(PurePosixPath(path))
        try:
            self.info(path)
            return True
        except NotFoundError:
            return False

    def delete(self, path: StrPath):
        path = str(PurePosixPath(path))
        if self.token:
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, req_nonce = prepare_encrypted_request_kwargs(
                "DELETE",
                url,
                self.token,
                path,
            )
        else:
            url = f"{self._client.base_url.rstrip('/')}/{get_api_path(self.dir_id, path)}"
            kwargs, req_nonce = prepare_request_kwargs("DELETE", url, self.token, {})
        self._send_request("DELETE", url, kwargs, req_nonce)

    def iterdir(self, path: StrPath | None = None) -> Iterator[Metadata]:
        yield from self.list(path)

    def glob(
        self, pattern: str, path: StrPath | None = None, *, case_sensitive: bool = True
    ) -> Iterator[Metadata]:
        def _match_cs(name: str, pat: str) -> bool:
            return fnmatch.fnmatchcase(name, pat)

        def _match_ci(name: str, pat: str) -> bool:
            return fnmatch.fnmatchcase(name.casefold(), pat.casefold())

        fncomp = _match_cs if case_sensitive else _match_ci
        for item in self.list(path):
            if item.is_dir:
                continue
            if fncomp(item.name, pattern):
                yield item

    def walk(
        self, path: StrPath | None = None
    ) -> Iterator[tuple[str, list[Metadata], list[Metadata]]]:
        p = PurePosixPath(path) if path is not None else None
        items = self.list(p)
        subdirs = [m for m in items if m.is_dir]
        files = [m for m in items if not m.is_dir]
        yield (str(p) if p is not None else "", subdirs, files)
        for sub in subdirs:
            child = (p / sub.name) if p is not None else PurePosixPath(sub.name)
            yield from self.walk(child)

    @contextmanager
    def open(
        self,
        path: StrPath,
        mode: str = "r",
        encoding: Optional[str] = None,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ):
        path = str(PurePosixPath(path))
        if "w" in mode:
            handle = _WriteHandle(self, path, encoding=encoding)
            try:
                yield handle
            finally:
                handle.close()
        elif "r" in mode:
            with self.read_stream(
                path,
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
        self.client = httpx.Client(base_url=self.base_url)

    def location(self, dir_id: str, token: Optional[str] = None) -> Location:
        return Location(self, dir_id, token)

    at = location

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
