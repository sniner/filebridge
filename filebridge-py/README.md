# Filebridge Python Client

A Python client library for interacting with the [Filebridge daemon](https://github.com/sniner/filebridge) (`filebridged`). Built on `httpx` and `pydantic`, it provides synchronous and asynchronous access to remote files via the filebridge REST API, including chunked streaming and transparent ChaCha20Poly1305 encryption when a token is configured.

## Requirements

- Python >= 3.10
- `httpx` >= 0.28.1
- `pydantic` >= 2.12.5
- `cryptography` >= 44.0.0

## Features

- **Asynchronous & Synchronous Client**: Full native support for async and sync Python environments.
- **Streaming Files**: Memory-efficient chunked streaming via `stream_read` and `write_stream`.
- **Automatic Encryption**: Secure ChaCha20Poly1305 AEAD streaming encryption natively handled whenever a token is used.
- **Metadata Privacy**: In token mode, file paths and parameters are transmitted encrypted — not visible in the URL.
- **SHA-256 Hashing**: `info(extensive=True)` / `stat(extensive=True)` requests the server to compute and return the SHA-256 hash of a file. Results are cached server-side and only recomputed when the file changes.
- **Glob Matching**: `glob()` supports `case_sensitive=False` for case-insensitive file name matching (portable across Linux and Windows).

## Usage

```python
from filebridge import FileBridgeClient

client = FileBridgeClient("http://localhost:8000")
loc = client.location("demo", token="my-secret-token")

# Read metadata for a file
info = loc.info("/path/to/file.txt")
print(f"File size: {info.size} bytes")

# Read metadata including SHA-256 hash (computed and cached server-side)
info = loc.info("/path/to/file.txt", extensive=True)
print(f"SHA-256: {info.sha256}")

# stat() is an alias for info()
meta = loc.stat("/path/to/file.txt", extensive=True)

# Read a file
data = loc.read("/path/to/file.txt")

# Write a file
loc.write("/path/to/file.txt", b"Hello, World!")

# Glob — case-insensitive on all platforms
for item in loc.glob("*.txt", case_sensitive=False):
    print(item.name)
```
