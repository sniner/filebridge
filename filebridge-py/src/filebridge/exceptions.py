"""Exception types for the filebridge client."""

from __future__ import annotations


class FileBridgeError(Exception):
    """Base exception for FileBridge."""

    pass


class AuthenticationError(FileBridgeError):
    """Raised when authentication fails (401/403)."""

    pass


class UnverifiedResponseError(AuthenticationError):
    """Raised when a location with a token answers with something other than
    an encrypted response.

    That is the case when the server rejects the request before it is
    authenticated (wrong token, clocks more than 30 seconds apart), when the
    server is older than 0.5, when a proxy answers in its place, and when the
    response was altered in transit. The status and text in the message are
    what arrived and prove nothing about the outcome of the operation.
    """

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
