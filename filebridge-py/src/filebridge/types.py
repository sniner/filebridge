"""Shared type aliases and protocols for the filebridge package."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any, Protocol, runtime_checkable

from .models import Metadata

StrPath = str | PurePosixPath


@runtime_checkable
class LocationProtocol(Protocol):
    """Interface that LocationEntry expects from a location implementation."""

    @property
    def case_sensitive(self) -> bool: ...

    def stat(self, path: StrPath, *, extensive: bool = False) -> Metadata: ...

    def glob(
        self,
        pattern: str,
        path: StrPath | None = None,
        *,
        extensive: bool = False,
    ) -> Iterator[Any]: ...

    def iterdir(
        self, path: StrPath | None = None, *, extensive: bool = False
    ) -> Iterator[Any]: ...

    def walk(
        self, path: StrPath | None = None, *, extensive: bool = False
    ) -> Iterator[Any]: ...

    def write(
        self,
        path: StrPath,
        data: bytes,
        *,
        offset: int | None = None,
    ) -> None: ...
