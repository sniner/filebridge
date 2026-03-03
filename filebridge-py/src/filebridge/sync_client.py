from __future__ import annotations

import io
from contextlib import contextmanager
from typing import ContextManager, List, Optional, overload

import httpx

from .core import (
    build_encrypted_write_body,
    decode_read_response,
    get_api_path,
    handle_response_errors,
    parse_json_response,
    prepare_request_kwargs,
)
from .exceptions import AuthenticationError, FileBridgeError, IsDirectoryError, NotFoundError
from .io import FileBridgeReadStream
from .models import ListResponse, Metadata


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
        path: str,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> bytes:
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
        if self.token:
            headers["Accept"] = "application/vnd.filebridge.stream"

        response = self._send_request("GET", url, kwargs, req_nonce)

        return decode_read_response(
            self.token,
            response.headers.get("Content-Type", ""),
            response.content,
            response.request.headers.get("X-Signature"),
            path,
        )

    def write(self, path: str, data: bytes, offset: Optional[int] = None):
        api_path = get_api_path(self.dir_id, path)
        params = {}
        if offset is not None:
            params["offset"] = offset

        headers = {"Content-Type": "application/octet-stream"}
        if self.token:
            headers["Content-Type"] = "application/vnd.filebridge.stream"

        url = f"{self._client.base_url.rstrip('/')}/{api_path}"
        kwargs, req_nonce = prepare_request_kwargs(
            "PUT", url, self.token, {"params": params, "headers": headers}
        )

        if self.token:
            sig = kwargs.get("headers", {}).get("X-Signature", "")
            kwargs["content"] = build_encrypted_write_body(self.token, sig, data)
            self._send_request("PUT", url, kwargs, req_nonce)
        else:
            kwargs["content"] = data
            self._send_request("PUT", url, kwargs, req_nonce)

    @overload
    def stream_read(
        self,
        path: str,
        offset: Optional[int] = ...,
        length: Optional[int] = ...,
        encoding: None = None,
    ) -> ContextManager[FileBridgeReadStream]: ...

    @overload
    def stream_read(
        self,
        path: str,
        offset: Optional[int] = ...,
        length: Optional[int] = ...,
        *,
        encoding: str,
    ) -> ContextManager[io.TextIOWrapper]: ...

    @contextmanager
    def stream_read(
        self,
        path: str,
        offset: Optional[int] = None,
        length: Optional[int] = None,
        encoding: Optional[str] = None,
    ):
        api_path = get_api_path(self.dir_id, path)
        params = {}
        if offset is not None:
            params["offset"] = offset
        if length is not None:
            params["length"] = length

        headers = {"Accept": "application/octet-stream"}
        if self.token:
            headers["Accept"] = "application/vnd.filebridge.stream"

        url = f"{self._client.base_url.rstrip('/')}/{api_path}"
        kwargs, req_nonce = prepare_request_kwargs(
            method="GET",
            url=url,
            token=self.token,
            kwargs={"params": params, "headers": headers},
        )
        headers = kwargs.setdefault("headers", {})

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

    def write_stream(self, path: str, stream, offset: Optional[int] = None):
        api_path = get_api_path(self.dir_id, path)
        params = {}
        if offset is not None:
            params["offset"] = offset

        headers = {"Content-Type": "application/octet-stream"}
        if self.token:
            headers["Content-Type"] = "application/vnd.filebridge.stream"

        url = f"{self._client.base_url.rstrip('/')}/{api_path}"
        kwargs, req_nonce = prepare_request_kwargs(
            "PUT", url, self.token, {"params": params, "headers": headers}
        )

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
            from .stream import (
                StreamAead,
                encode_data,
                encode_stop,
            )

            token = self.token
            assert token is not None

            def signed_chunk_generator():
                sig = kwargs.get("headers", {}).get("X-Signature", "")
                aead = StreamAead(token, sig)
                for chunk in chunk_generator():
                    encrypted_chunk = aead.encrypt(chunk)
                    yield encode_data(encrypted_chunk)

                yield encode_stop(aead.finalize())

            kwargs["content"] = signed_chunk_generator()
            self._send_request("PUT", url, kwargs, req_nonce)
        else:
            kwargs["content"] = chunk_generator()
            self._send_request("PUT", url, kwargs, req_nonce)

    def list(self, path: Optional[str] = None) -> List[Metadata]:
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

    def info(self, path: str) -> Metadata:
        url = f"{self._client.base_url.rstrip('/')}/{get_api_path(self.dir_id, path)}"
        kwargs, req_nonce = prepare_request_kwargs("GET", url, self.token, {})
        response = self._send_request("GET", url, kwargs, req_nonce)
        sig = response.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, response.content)
        return Metadata(**data)

    def exists(self, path: str) -> bool:
        try:
            self.info(path)
            return True
        except NotFoundError:
            return False

    def delete(self, path: str):
        url = f"{self._client.base_url.rstrip('/')}/{get_api_path(self.dir_id, path)}"
        kwargs, req_nonce = prepare_request_kwargs("DELETE", url, self.token, {})
        self._send_request("DELETE", url, kwargs, req_nonce)


class FileBridgeClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.client = httpx.Client(base_url=self.base_url)

    def location(self, dir_id: str, token: Optional[str] = None) -> Location:
        return Location(self, dir_id, token)

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
