"""Filename comparison strategies (case-sensitive / case-insensitive)."""

from __future__ import annotations

import fnmatch
from abc import ABC, abstractmethod
from typing import Type


class FilenameComparator(ABC):
    """Strategy for comparing filenames (case-sensitive or case-insensitive)."""

    def __init__(self, base: str):
        self.base = self.normalize(str(base))

    @abstractmethod
    def normalize(self, name: str) -> str: ...

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.base == self.normalize(other)
        elif isinstance(other, self.__class__):
            return self.base == other.base
        return NotImplemented

    def match(self, name: str) -> bool:
        return fnmatch.fnmatchcase(self.normalize(name), self.base)

    def equals(self, name: str) -> bool:
        return self.base == self.normalize(str(name))

    @classmethod
    def compare(cls, a: str, b: str) -> bool:
        return cls(a).equals(b)

    @staticmethod
    def build(*, case_sensitive: bool) -> Type[FilenameComparator]:
        if case_sensitive:
            return CaseSensitiveComparator
        return CaseInsensitiveComparator


class CaseSensitiveComparator(FilenameComparator):
    def normalize(self, name: str) -> str:
        return name


class CaseInsensitiveComparator(FilenameComparator):
    def normalize(self, name: str) -> str:
        return name.casefold()
