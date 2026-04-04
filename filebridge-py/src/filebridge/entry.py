"""LocationEntry — a pathlib-like handle to a file or directory within a location."""

from __future__ import annotations

import io
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ContextManager, Literal, overload

from .comparator import CaseInsensitiveComparator
from .io import FileBridgeReadStream
from .models import Metadata
from .types import LocationProtocol, StrPath

if TYPE_CHECKING:
    from .location import _WriteHandle


class LocationEntry:
    """A pathlib-like handle to a file or directory within a location.

    Supports path operations (``/``, ``name``, ``stem``, ``suffix``, ``parent``),
    metadata access (``stat()``, ``is_dir()``, ``is_file()``), directory traversal
    (``iterdir()``, ``glob()``, ``walk()``), and file I/O (``open()``).

    Instances are obtained from ``Location.list()``, ``Location.iterdir()``,
    ``Location.glob()``, or by joining paths with ``/``.
    """

    def __init__(
        self,
        loc: LocationProtocol,
        path: LocationPath,
        metadata: Metadata | None = None,
    ):
        self._location = loc
        self._path = PurePosixPath(path)
        self._stat = metadata

    def __fspath__(self) -> str:
        return str(self.path)

    @property
    def path(self) -> PurePosixPath:
        return self._path

    def is_dir(self) -> bool:
        return self.stat().is_dir

    def is_file(self) -> bool:
        return not self.is_dir()

    def _refresh(self, *, extensive: bool | None = None) -> Metadata:
        ex = self._stat is not None and self._stat.sha256 is not None
        return self._location.stat(self._path, extensive=ex if extensive is None else extensive)

    def refresh(self, *, extensive: bool | None = None) -> LocationEntry:
        """Re-fetch metadata from the server and return ``self``."""
        self._stat = self._refresh(extensive=extensive)
        return self

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def stem(self) -> str:
        return self._path.stem

    @property
    def suffix(self) -> str:
        return self._path.suffix

    @property
    def suffixes(self) -> list[str]:
        return self._path.suffixes

    @property
    def parent(self) -> PurePosixPath:
        return self._path.parent

    @property
    def location(self) -> LocationProtocol:
        return self._location

    def is_relative_to(self, other: LocationPath) -> bool:
        if isinstance(other, LocationEntry):
            if self._location != other._location:
                return False
            other_path = other.path
        else:
            other_path = PurePosixPath(other)

        if self._location.case_sensitive:
            # pathlib.Path.is_relative_to() is always case-sensitive
            return self.path.is_relative_to(other_path)

        if len(self.path.parts) < len(other_path.parts):
            return False

        cmp = CaseInsensitiveComparator
        for t, o in zip(self.path.parts, other_path.parts):
            if not cmp.compare(t, o):
                return False
        return True

    def stat(self, *, extensive: bool | None = None, refresh: bool = False) -> Metadata:
        """Return cached metadata, fetching from the server if needed.

        Args:
            extensive: Request SHA-256 hash. Defaults to preserving the
                current state (extensive if already fetched with hash).
            refresh: Force re-fetching metadata from the server.
        """
        if self._stat is None:
            self._stat = self._refresh(extensive=extensive)
        elif refresh or (extensive and self._stat.sha256 is None):
            self._stat = self._refresh(extensive=extensive)
        return self._stat

    def glob(self, pattern: str, *, extensive: bool = False) -> Iterator[LocationEntry]:
        """Iterate over entries matching *pattern* relative to this entry."""
        yield from self._location.glob(pattern, self._path, extensive=extensive)

    def iterdir(self, *, extensive: bool = False) -> Iterator[LocationEntry]:
        """Iterate over the entries in this directory.

        Raises:
            NotADirectoryError: If this entry is not a directory.
        """
        if not self.is_dir():
            raise NotADirectoryError(f"{self._path} is not a directory")
        yield from self._location.iterdir(self._path, extensive=extensive)

    def walk(
        self, *, extensive: bool = False
    ) -> Iterator[tuple[PurePosixPath, list[LocationEntry], list[LocationEntry]]]:
        """Walk the directory tree, yielding ``(dirpath, subdirs, files)`` tuples."""
        yield from self._location.walk(self._path, extensive=extensive)

    def __truediv__(self, other: LocationPath) -> LocationEntry:
        if isinstance(other, LocationEntry):
            if self._location != other._location:
                raise ValueError("Cannot join paths from different locations")
            other_path = other.path
        else:
            other_path = PurePosixPath(other)
        new_path = self._path / other_path
        return LocationEntry(self._location, new_path)

    @overload
    def open(
        self,
        mode: Literal["w", "wb"],
        *,
        encoding: str | None = ...,
    ) -> ContextManager[_WriteHandle]: ...

    @overload
    def open(
        self,
        mode: Literal["r", "rb"] = ...,
        *,
        encoding: None = ...,
        offset: int | None = ...,
        length: int | None = ...,
    ) -> ContextManager[FileBridgeReadStream]: ...

    @overload
    def open(
        self,
        mode: Literal["r", "rb"] = ...,
        *,
        encoding: str,
        offset: int | None = ...,
        length: int | None = ...,
    ) -> ContextManager[io.TextIOWrapper]: ...

    @contextmanager
    def open(
        self,
        mode: str = "r",
        *,
        encoding: str | None = None,
        offset: int | None = None,
        length: int | None = None,
    ):
        """Open this entry for reading or writing.

        Args:
            mode: ``"r"``/``"rb"`` for reading, ``"w"``/``"wb"`` for writing.
            encoding: Text encoding. When set in read mode, returns a
                ``TextIOWrapper``; in write mode, encodes strings before sending.
            offset: Start reading at this byte offset (read mode only).
            length: Read at most this many bytes (read mode only).
        """
        with self._location.open(  # type: ignore[attr-defined]
            self._path,
            mode=mode,
            encoding=encoding,
            offset=offset,
            length=length,
        ) as f:
            yield f

    def __str__(self) -> str:
        return str(self.path)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(path={self.path!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, LocationEntry):
            return NotImplemented
        if self._location != other._location:
            return False
        if self._location.case_sensitive:
            return self.path == other.path
        else:
            if len(self.path.parts) != len(other.path.parts):
                return False
            cmp = CaseInsensitiveComparator
            for t, o in zip(self.path.parts, other.path.parts):
                if not cmp.compare(t, o):
                    return False
        return True

    def __hash__(self) -> int:
        if self._location.case_sensitive:
            return hash((self._location, self._path))
        else:
            parts = tuple(p.casefold() for p in self._path.parts)
            return hash((self._location, parts))


LocationPath = StrPath | LocationEntry
