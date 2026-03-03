from __future__ import annotations

from pydantic import BaseModel


class Metadata(BaseModel):
    name: str
    is_dir: bool
    size: int | None = None
    mdate: str | None = None
    sha256: str | None = None


class ListResponse(BaseModel):
    items: list[Metadata]
    detail: str | None = None
