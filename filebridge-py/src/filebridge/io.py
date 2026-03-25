from __future__ import annotations

import io

import httpx

from .exceptions import FileBridgeError
from .stream import StreamAead, StreamDecoder, StreamError


class FileBridgeReadStream(io.RawIOBase):
    def __init__(self, response: httpx.Response, token: str | None = None):
        self._response = response
        self._token = token
        self._iter = response.iter_bytes()
        self._buffer = bytearray()
        self._eof = False

        self._is_verified = "application/vnd.filebridge.stream" in response.headers.get(
            "Content-Type", ""
        )
        self._decoder = None

        if self._is_verified:
            signature = response.request.headers.get("X-Signature")
            if not signature or not self._token:
                raise FileBridgeError("Missing signature for stream verification")
            self._decoder = StreamDecoder()
            self._aead = StreamAead(self._token, signature)

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def readable(self) -> bool:
        return True

    def close(self):
        self._response.close()
        super().close()

    def _fill_buffer(self) -> bool:
        """Reads from HTTP stream into buffer. Returns True if data was added, False if EOF."""
        if self._eof:
            return False

        if not self._is_verified:
            try:
                chunk = next(self._iter)
                if chunk:
                    self._buffer.extend(chunk)
                    return True
                return False
            except StopIteration:
                self._eof = True
                return False

        # Verified stream logic
        decoder = self._decoder
        aead = self._aead
        assert decoder is not None and aead is not None

        while not self._eof:
            frame = decoder.next_frame()
            if frame:
                tag, sig_str, payload = frame
                if tag == "DATA":
                    try:
                        self._buffer.extend(aead.decrypt(payload))
                        return True
                    except StreamError:
                        raise FileBridgeError("Chunk Authenticated Decryption Failed")
                elif tag == "STOP":
                    if not sig_str:
                        raise FileBridgeError("Stop frame missing signature")
                    try:
                        aead.verify_stop(sig_str)
                    except StreamError:
                        raise FileBridgeError("Stop signature mismatch")
                    self._eof = True
                    return False
            else:
                try:
                    decoder.push(next(self._iter))
                except StopIteration:
                    raise FileBridgeError("Unexpected EOF before STOP frame")

        return bool(self._buffer)

    def readinto(self, b) -> int:
        if not self._buffer and not self._eof:
            self._fill_buffer()

        if not self._buffer:
            return 0

        length = min(len(b), len(self._buffer))
        b[:length] = self._buffer[:length]
        del self._buffer[:length]
        return length

    def read(self, size: int = -1) -> bytes:
        if size == -1 or size is None:
            while not self._eof:
                self._fill_buffer()
            res = bytes(self._buffer)
            self._buffer.clear()
            return res

        while len(self._buffer) < size and not self._eof:
            self._fill_buffer()

        length = min(size, len(self._buffer))
        res = bytes(self._buffer[:length])
        del self._buffer[:length]
        return res
