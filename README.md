# Filebridge

Filebridge provides a secure, lightweight REST API for remote file access. It is designed for environments (like Docker) where you need to read or write files across service boundaries without direct volume mounts.

## Features

- **Granular Access**: Map multiple local directories ("locations") to unique IDs.
- **HMAC Security**: Optional per-location secret tokens for request signing.
- **Tamper Protection**: Signatures cover the timestamp, HTTP method, and URI. Payload integrity is validated via AEAD.
- **Metadata Privacy**: In token mode, file paths and parameters are transmitted in an encrypted request body — not in the URL. Only the location name remains visible.
- **End-to-End Encryption**: When using token authentication, all file transfers are automatically encrypted using ChaCha20Poly1305 (AEAD).
- **Chunked Access**: Supports `offset` and `length` for partial file reads and writes.
- **Binary & Streaming**: Files are transferred via raw binary data or highly efficient chunked streaming (`application/vnd.filebridge.stream`).

## Components

The project consists of several independent components, each with its own documentation:

- [`filebridged`](./filebridged/README.md): The server daemon (Rust/Axum) providing the REST API.
- [`filebridge`](./filebridge/README.md): A high-level Rust library for interacting with the server.
- [`filebridge-cli`](./filebridge-cli/README.md): The command-line interface.
- [`filebridge-mcp`](./filebridge-mcp/README.md): An MCP server (stdio transport) for Claude Code and other MCP clients.
- [`filebridge-py`](./filebridge-py/README.md): A Python library for interacting with the server.

Please refer to the individual component directories for setup instructions, configuration details, and usage examples.

## Security: HMAC Signing

When a `token` is configured for a location, every request must include:
- `X-Timestamp`: Current Unix timestamp (UTC seconds).
- `X-Signature`: Hex-encoded HMAC-SHA256 signature.

The signature is calculated by combining the token, timestamp, HTTP method, and the fully qualified URI (path + query parameters). 

Requests older than 300 seconds (5 minutes) are automatically rejected to prevent replay attacks.

**Automatic Encryption (AEAD):** When token authentication is used, the file payload is automatically and transparently encrypted using **ChaCha20Poly1305**. The cipher key and nonce are derived via **HKDF-SHA256** from the token and the request's `X-Signature`, with separate derivation contexts for stream data and JSON responses. The AEAD cipher provides both data confidentiality and chunk-wise integrity in a single pass.

**Metadata Privacy:** In token mode, the file path and any parameters (offset, length) are never exposed in the URL. They are sent in an encrypted JSON body (`Content-Type: application/vnd.filebridge.request`), also protected by ChaCha20Poly1305. The only information visible to a network observer is the HTTP method and the location name in the URL — no file paths, no offsets, no operation details.

## License

BSD-3-Clause
