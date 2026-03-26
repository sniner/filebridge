from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, field_validator


class Metadata(BaseModel):
    name: str
    is_dir: bool
    size: int | None = None
    mdate: datetime | None = None
    sha256: str | None = None

    @field_validator("mdate", mode="before")
    def parse_mdate(cls, value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except (ValueError, TypeError):
                return None
        return None


class ListResponse(BaseModel):
    items: list[Metadata]
    detail: str | None = None
