# Filebridge Python Client

A Python client library for interacting with the [Filebridge daemon](https://github.com/sniner/filebridge) (`filebridged`). Built on `httpx` and `pydantic`, it provides synchronous and asynchronous access to remote files via the filebridge REST API, including chunked streaming and transparent ChaCha20Poly1305 encryption when a token is configured.

## Requirements

- Python >= 3.13
- `httpx` >= 0.28.1
- `pydantic` >= 2.12.5
- `cryptography` >= 44.0.0

## Features

- **Asynchronous & Synchronous Client**: Full native support for async and sync Python environments.
- **Streaming Files**: Memory-efficient chunked streaming via `stream_read` and `write_stream`.
- **Automatic Encryption**: Secure ChaCha20Poly1305 AEAD streaming encryption natively handled whenever a token is used.
- **Metadata Privacy**: In token mode, file paths and parameters are transmitted encrypted — not visible in the URL.

## Usage

```python
from filebridge import FileBridgeClient

client = FileBridgeClient("http://localhost:8000")
loc = client.location("demo", token="my-secret-token")

# Read metadata for a file
info = loc.info("/path/to/file.txt")
print(f"File size: {info.size} bytes")

# Read a file
data = loc.read("/path/to/file.txt")

# Write a file
loc.write("/path/to/file.txt", b"Hello, World!")
```
