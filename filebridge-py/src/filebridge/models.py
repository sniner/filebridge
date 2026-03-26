from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, field_validator


class Metadata(BaseModel):
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
    items: list[Metadata]
    detail: str | None = None
