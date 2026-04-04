"""Directory traversal: glob and walk operations for Filebridge locations."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Type

from .comparator import (
    CaseInsensitiveComparator,
    CaseSensitiveComparator,
    FilenameComparator,
)

if TYPE_CHECKING:
    from .entry import LocationEntry
    from .types import LocationProtocol


def glob_entries(
    loc: LocationProtocol,
    pattern: str,
    path: str | None,
    *,
    case_sensitive: bool,
    extensive: bool = False,
) -> Iterator[LocationEntry]:
    """Iterate over entries matching a glob *pattern*.

    Supports ``*``, ``?``, ``[seq]``, and recursive ``**`` patterns.
    """
    parts = PurePosixPath(pattern).parts
    base = str(PurePosixPath(path or ""))
    if base == ".":
        base = ""

    comparator = CaseSensitiveComparator if case_sensitive else CaseInsensitiveComparator
    return _recursive_glob(loc, base, parts, comparator, extensive=extensive)


def _recursive_glob(
    loc: LocationProtocol,
    current_path: str,
    pattern_parts: tuple[str, ...],
    comparator: Type[FilenameComparator],
    current_items: list[LocationEntry] | None = None,
    *,
    extensive: bool = False,
) -> Iterator[LocationEntry]:
    if not pattern_parts:
        return

    pattern = pattern_parts[0]
    remaining = pattern_parts[1:]

    def get_items() -> list[LocationEntry]:
        if current_items is not None:
            return current_items
        return list(loc.list(current_path, extensive=extensive))

    # Special case: recursive wildcard **
    if pattern == "**":
        items = get_items()

        # 1. Apply remaining pattern at current directory (zero depth)
        if remaining:
            yield from _recursive_glob(
                loc,
                current_path,
                remaining,
                comparator,
                items,
                extensive=extensive,
            )
        else:
            # Bare ** without remainder: list everything recursively
            yield from _walk_all(loc, current_path, items, extensive=extensive)
            return

        # 2. Recurse into subdirectories and continue ** there
        for item in items:
            if item.is_dir():
                yield from _recursive_glob(
                    loc,
                    str(item.path),
                    pattern_parts,
                    comparator,
                    extensive=extensive,
                )
        return

    cmp = comparator(pattern)

    for item in get_items():
        if cmp.match(item.name):
            if not remaining:
                # End of pattern reached
                yield item
            elif item.is_dir():
                # Recurse with remaining pattern parts
                yield from _recursive_glob(
                    loc,
                    str(item.path),
                    remaining,
                    comparator,
                    extensive=extensive,
                )


def _walk_all(
    loc: LocationProtocol,
    path: str,
    current_items: list[LocationEntry] | None = None,
    *,
    extensive: bool = False,
) -> Iterator[LocationEntry]:
    """Helper for bare ** pattern: yield all entries recursively."""
    items = current_items if current_items is not None else loc.list(path, extensive=extensive)
    for item in items:
        yield item
        if item.is_dir():
            yield from _walk_all(loc, str(item.path), extensive=extensive)


def walk_entries(
    loc: LocationProtocol,
    path: str | None = None,
    *,
    extensive: bool = False,
) -> Iterator[tuple[PurePosixPath, list[LocationEntry], list[LocationEntry]]]:
    """Walk the directory tree, yielding ``(dirpath, subdirs, files)`` tuples.

    Similar to ``os.walk()``.
    """
    p = PurePosixPath(path or "")
    all_items = list(loc.list(p, extensive=extensive))
    subdirs = [m for m in all_items if m.is_dir()]
    files = [m for m in all_items if not m.is_dir()]
    yield (p, subdirs, files)
    for sub in subdirs:
        yield from walk_entries(loc, str(p / sub.name), extensive=extensive)
