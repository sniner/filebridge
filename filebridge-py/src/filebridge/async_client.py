from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncContextManager, List, Optional, overload

import httpx

from .core import (
    build_encrypted_envelope,
    build_encrypted_write_body,
    decode_read_response,
    get_api_path,
    handle_response_errors,
    parse_json_response,
    prepare_encrypted_request_kwargs,
    prepare_request_kwargs,
)
from .exceptions import AuthenticationError, FileBridgeError, IsDirectoryError, NotFoundError
from .io import AsyncFileBridgeReadStream
from .models import ListResponse, Metadata


class AsyncLocation:
    def __init__(self, client: AsyncFileBridgeClient, dir_id: str, token: Optional[str] = None):
        self.dir_id = dir_id
        self.token = token
        self._client = client

    async def _send_request(
        self, method: str, path: str, req_nonce: Optional[str] = None, **kwargs
    ) -> httpx.Response:
        url = f"{self._client.base_url.rstrip('/')}/{get_api_path(self.dir_id, path)}"
        kwargs, generated_nonce = prepare_request_kwargs(
            method=method,
            url=url,
            token=self.token,
            kwargs=kwargs,
        )
        expected_nonce = req_nonce if req_nonce is not None else generated_nonce

        resp = await self._client.client.request(method, url, **kwargs)

        if not resp.is_success:
            handle_response_errors(resp.status_code, resp.text)
            raise FileBridgeError(f"HTTP Error {resp.status_code}: {resp.text}")

        if self.token:
            resp_nonce = resp.headers.get("X-Nonce")
            if resp_nonce != expected_nonce:
                raise AuthenticationError("Nonce mismatch")
        return resp

    async def _send_encrypted_request(
        self,
        method: str,
        path: str,
        offset: Optional[int] = None,
        length: Optional[int] = None,
    ) -> httpx.Response:
        """Send a request with path in encrypted body (token-mode)."""
        assert self.token is not None
        api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
        url = f"{self._client.base_url.rstrip('/')}/{api_path}"
        kwargs, req_nonce = prepare_encrypted_request_kwargs(
            method,
            url,
            self.token,
            path,
            offset=offset,
            length=length,
        )
        resp = await self._client.client.request(method, url, **kwargs)

        if not resp.is_success:
            handle_response_errors(resp.status_code, resp.text)
            raise FileBridgeError(f"HTTP Error {resp.status_code}: {resp.text}")

        resp_nonce = resp.headers.get("X-Nonce")
        if resp_nonce != req_nonce:
            raise AuthenticationError("Nonce mismatch")
        return resp

    async def read(
        self, path: str, offset: Optional[int] = None, length: Optional[int] = None
    ) -> bytes:
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
            resp = await self._client.client.request("GET", url, **kwargs)
            if not resp.is_success:
                handle_response_errors(resp.status_code, resp.text)
                raise FileBridgeError(f"HTTP Error {resp.status_code}: {resp.text}")
            resp_nonce = resp.headers.get("X-Nonce")
            if resp_nonce != req_nonce:
                raise AuthenticationError("Nonce mismatch")
        else:
            api_path = get_api_path(self.dir_id, path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            if length is not None:
                params["length"] = length
            headers = {"Accept": "application/octet-stream"}
            resp = await self._send_request("GET", api_path, params=params, headers=headers)

        return decode_read_response(
            self.token,
            resp.headers.get("Content-Type", ""),
            resp.content,
            resp.request.headers.get("X-Signature"),
            path,
        )

    async def write(self, path: str, data: bytes, offset: Optional[int] = None):
        if self.token:
            # Token mode: path in META frame, not URL
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, _ = prepare_request_kwargs(
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
            req_nonce = kwargs.get("headers", {}).get("X-Nonce")
            resp = await self._client.client.request("PUT", url, **kwargs)
            if not resp.is_success:
                handle_response_errors(resp.status_code, resp.text)
                raise FileBridgeError(f"HTTP Error {resp.status_code}: {resp.text}")
            if resp.headers.get("X-Nonce") != req_nonce:
                raise AuthenticationError("Nonce mismatch")
        else:
            api_path = get_api_path(self.dir_id, path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, _ = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"params": params, "headers": {"Content-Type": "application/octet-stream"}},
            )
            kwargs["content"] = data
            await self._send_request("PUT", path, **kwargs)

    @overload
    def stream_read(
        self,
        path: str,
        offset: Optional[int] = ...,
        length: Optional[int] = ...,
        encoding: None = None,
    ) -> AsyncContextManager[AsyncFileBridgeReadStream]: ...

    @overload
    def stream_read(
        self,
        path: str,
        offset: Optional[int] = ...,
        length: Optional[int] = ...,
        *,
        encoding: str,
    ) -> AsyncContextManager[AsyncFileBridgeReadStream]: ...

    @asynccontextmanager
    async def stream_read(
        self,
        path: str,
        offset: Optional[int] = None,
        length: Optional[int] = None,
        encoding: Optional[str] = None,
    ):
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

        async with self._client.client.stream("GET", url, **kwargs) as resp:
            if not resp.is_success:
                await resp.aread()
                handle_response_errors(resp.status_code, resp.text)
                raise FileBridgeError(f"HTTP Error {resp.status_code}: {resp.text}")

            if self.token:
                resp_nonce = resp.headers.get("X-Nonce")
                if resp_nonce != req_nonce:
                    raise AuthenticationError("Nonce mismatch")

            content_type = resp.headers.get("Content-Type", "")
            if "application/json" in content_type:
                body = await resp.aread()
                sig = resp.request.headers.get("X-Signature", "") if self.token else None
                data = parse_json_response(self.token, sig, body)
                if "items" in data:
                    raise IsDirectoryError(f"{path} is a directory")

            raw_stream = AsyncFileBridgeReadStream(resp, self.token)
            if encoding:
                raise NotImplementedError(
                    "TextIOWrapper is not supported for async streams directly."
                )
            else:
                async with raw_stream as stream:
                    yield stream

    async def write_stream(self, path: str, stream, offset: Optional[int] = None):
        async def chunk_generator():
            import inspect

            if hasattr(stream, "read"):
                while True:
                    result = stream.read(64 * 1024)
                    if inspect.isawaitable(result):
                        chunk = await result
                    else:
                        chunk = result
                    if not chunk:
                        break
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    yield chunk
            elif hasattr(stream, "__aiter__"):
                async for chunk in stream:
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    yield chunk
            else:
                for chunk in stream:
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    yield chunk

        if self.token:
            token = self.token

            from .stream import (
                StreamAead,
                encode_data,
                encode_meta,
                encode_stop,
            )

            # Token mode: path in META frame, not URL
            api_path = get_api_path(self.dir_id, None, use_encrypted_body=True)
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, _ = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"headers": {"Content-Type": "application/vnd.filebridge.stream"}},
            )

            async def signed_chunk_generator():
                sig = kwargs.get("headers", {}).get("X-Signature", "")
                # Emit META frame first with encrypted envelope
                envelope = build_encrypted_envelope(token, sig, path, offset)
                yield encode_meta(envelope.encode())

                aead = StreamAead(token, sig)
                async for chunk in chunk_generator():
                    encrypted_chunk = aead.encrypt(chunk)
                    yield encode_data(encrypted_chunk)
                yield encode_stop(aead.finalize())

            kwargs["content"] = signed_chunk_generator()
            req_nonce = kwargs.get("headers", {}).get("X-Nonce")
            resp = await self._client.client.request("PUT", url, **kwargs)
            if not resp.is_success:
                handle_response_errors(resp.status_code, resp.text)
                raise FileBridgeError(f"HTTP Error {resp.status_code}: {resp.text}")
            if resp.headers.get("X-Nonce") != req_nonce:
                raise AuthenticationError("Nonce mismatch")
        else:
            api_path = get_api_path(self.dir_id, path)
            params = {}
            if offset is not None:
                params["offset"] = offset
            url = f"{self._client.base_url.rstrip('/')}/{api_path}"
            kwargs, _ = prepare_request_kwargs(
                "PUT",
                url,
                self.token,
                {"params": params, "headers": {"Content-Type": "application/octet-stream"}},
            )
            kwargs["content"] = chunk_generator()
            await self._send_request("PUT", path, **kwargs)

    async def list(self, path: Optional[str] = None) -> List[Metadata]:
        if self.token and path:
            resp = await self._send_encrypted_request("GET", path)
        else:
            api_path = get_api_path(self.dir_id, path)
            resp = await self._send_request("GET", api_path)

        sig = resp.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, resp.content)
        if "items" not in data:
            meta = Metadata(**data)
            return [meta]

        list_resp = ListResponse(**data)
        return list_resp.items

    async def info(self, path: str) -> Metadata:
        if self.token:
            resp = await self._send_encrypted_request("GET", path)
        else:
            api_path = get_api_path(self.dir_id, path)
            resp = await self._send_request("GET", api_path)
        sig = resp.request.headers.get("X-Signature", "") if self.token else None
        data = parse_json_response(self.token, sig, resp.content)
        return Metadata(**data)

    async def exists(self, path: str) -> bool:
        try:
            await self.info(path)
            return True
        except NotFoundError:
            return False

    async def delete(self, path: str):
        if self.token:
            await self._send_encrypted_request("DELETE", path)
        else:
            api_path = get_api_path(self.dir_id, path)
            await self._send_request("DELETE", api_path)


class AsyncFileBridgeClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/") + "/"
        self.client = httpx.AsyncClient(base_url=self.base_url)

    def location(self, dir_id: str, token: Optional[str] = None) -> AsyncLocation:
        return AsyncLocation(self, dir_id, token)

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
