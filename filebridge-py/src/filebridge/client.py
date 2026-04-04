"""FileBridgeClient — entry point for connecting to a Filebridge server."""

from __future__ import annotations

import httpx

from .location import Location


class FileBridgeClient:
    """Client for a Filebridge server.

    Use as a context manager to ensure the underlying HTTP connection is
    closed::

        with FileBridgeClient("http://localhost:8000") as client:
            loc = client.location("my-share")
            data = loc.read("hello.txt")

    Args:
        base_url: Server base URL (e.g. ``http://localhost:8000``).
        timeout: HTTP timeout in seconds. Defaults to ``30.0``.
    """

    def __init__(self, base_url: str, *, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/") + "/"
        self.client = httpx.Client(timeout=timeout)

    def location(
        self,
        dir_id: str,
        token: str | None = None,
        *,
        case_sensitive: bool = True,
    ) -> Location:
        """Return a ``Location`` handle for the given directory ID.

        Args:
            dir_id: Server-side directory identifier.
            token: Optional authentication token. When set, enables HMAC
                signing and end-to-end encryption.
            case_sensitive: Whether filename comparisons are case-sensitive.
        """
        return Location(self, dir_id, token, case_sensitive=case_sensitive)

    at = location

    def close(self):
        self.client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
