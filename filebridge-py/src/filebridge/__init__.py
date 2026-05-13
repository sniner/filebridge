"""Python client library for the Filebridge REST API.

Provides synchronous access to files on a Filebridge server with optional
HMAC authentication and ChaCha20-Poly1305 end-to-end encryption.

Quick start::

    from filebridge import FileBridgeClient

    client = FileBridgeClient("http://localhost:8000")
    loc = client.location("my-share")

    # List directory contents
    for entry in loc.iterdir():
        print(entry.name)

    # Read a file
    data = loc.read("hello.txt")

When a token is provided, requests are HMAC-signed and file content
is encrypted transparently::

    loc = client.location("my-share", token="secret")
"""

from .client import (
    FileBridgeClient,
)
from .entry import (
    LocationEntry,
)
from .exceptions import (
    AuthenticationError,
    FileBridgeError,
    FileBridgePermissionError,
    IsDirectoryError,
    NotFoundError,
)
from .io import (
    FileBridgeReadStream,
)
from .location import (
    Location,
)
from .models import (
    Metadata,
    Permissions,
)

__all__ = [
    "FileBridgeClient",
    "Location",
    "LocationEntry",
    "FileBridgeError",
    "AuthenticationError",
    "NotFoundError",
    "IsDirectoryError",
    "FileBridgePermissionError",
    "Metadata",
    "Permissions",
    "FileBridgeReadStream",
]
