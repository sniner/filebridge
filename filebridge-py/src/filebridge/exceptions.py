from __future__ import annotations


class FileBridgeError(Exception):
    """Base exception for FileBridge."""

    pass


class AuthenticationError(FileBridgeError):
    """Raised when authentication fails (401/403)."""

    pass


class NotFoundError(FileBridgeError):
    """Raised when a resource is not found (404)."""

    pass


class IsDirectoryError(FileBridgeError):
    """Raised when a file operation is attempted on a directory."""

    pass


class FileBridgePermissionError(FileBridgeError):
    """Raised when an operation is forbidden due to permissions (403)."""

    pass
