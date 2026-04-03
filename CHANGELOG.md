# Changelog

This format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.4] - 2026-04-03

### Added

- **Directory listings** now support `extensive` mode: when enabled, SHA-256 hashes for all files
  are included in the listing response, using the server-side hash cache
- **`list()`**, **`iterdir()`**, **`glob()`**, and **`walk()`** in the Python client accept
  `extensive=True` to request hashes in a single round-trip per directory instead of one request
  per file

## [0.2.3] - 2026-03-31

### Fixed

- **Rust client `read_stream`** no longer requests stream framing (`application/vnd.filebridge.stream`)
  for unauthenticated reads, which caused reqwest to stall on mismatched Content-Length
- **Server Content-Length** calculation now correctly omits AEAD overhead when no token is present

## [0.2.2] - 2026-03-30

### Added

- **API documentation** across all Rust crates and the Python client (docstrings, module docs,
  crate-level examples)

## [0.2.1] - 2026-03-27

### Added

- **`--log-level`** and **`--log-file`** options for `filebridged` with per-request tracing spans
  (method + location label)
- **`read_range()`** method on the Rust client, split from `read()` for partial reads
- **`filebridge-mcp`** added to the GitHub release workflow

### Changed

- **`Metadata.mtime`** in the Python client is now `datetime` instead of `str`
- **`Metadata.mtime`** in the Rust client is now `chrono::DateTime<Utc>` instead of `String`

## [0.2.0] - 2026-03-26

### Added

- **`ApiError`** enum across all Rust crates, replacing raw `StatusCode`-based error returns with
  typed variants for better error propagation
- **Model tests** for the Python client

### Changed

- **`Metadata.mtime`** in the Python client converted from raw string to `datetime`
- **Error handling** in REST API and MCP server uses structured `ApiError` variants instead of
  ad-hoc status codes
