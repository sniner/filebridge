"""Data models returned by the Filebridge API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, field_validator


class Metadata(BaseModel):
    """File or directory metadata returned by the server.

    Attributes:
        name: Entry name (not the full path).
        is_dir: Whether this entry is a directory.
        size: File size in bytes, ``None`` for directories.
        mtime: Last modification time.
        sha256: SHA-256 hash of the file content. Only present when
            requested via ``extensive=True``.
    """

    name: str
    is_dir: bool
    size: int | None = None
    mtime: datetime | None = None
    sha256: str | None = None

    @field_validator("mtime", mode="before")
    def parse_mtime(cls, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                # Deliberate: invalid date strings silently become None rather than
                # raising, so a single malformed mtime from the server doesn't break
                # the entire response.
                return None
        return None


class ListResponse(BaseModel):
    """Server response for directory listings."""

    items: list[Metadata]
    detail: str | None = None
