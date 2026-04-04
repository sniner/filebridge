"""Shared type aliases and protocols for the filebridge package."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .models import Metadata

if TYPE_CHECKING:
    from .entry import LocationEntry

StrPath = str | PurePosixPath


@runtime_checkable
class LocationProtocol(Protocol):
    """Interface that LocationEntry and traverse expect from a location implementation."""

    @property
    def case_sensitive(self) -> bool: ...

    def stat(self, path: StrPath, *, extensive: bool = False) -> Metadata: ...

    def list(
        self, path: StrPath | None = None, *, extensive: bool = False
    ) -> Iterator[LocationEntry]: ...

    def glob(
        self,
        pattern: str,
        path: StrPath | None = None,
        *,
        extensive: bool = False,
    ) -> Iterator[LocationEntry]: ...

    def iterdir(
        self, path: StrPath | None = None, *, extensive: bool = False
    ) -> Iterator[LocationEntry]: ...

    def walk(
        self, path: StrPath | None = None, *, extensive: bool = False
    ) -> Iterator[tuple[PurePosixPath, list[LocationEntry], list[LocationEntry]]]: ...

    def write(
        self,
        path: StrPath,
        data: bytes,
        *,
        offset: int | None = None,
    ) -> None: ...
