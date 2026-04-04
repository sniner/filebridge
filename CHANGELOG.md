# Changelog

This format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.7] - 2026-04-04

Refactoring of the Python client: split the monolithic `client.py` into separate modules
(`types`, `comparator`, `entry`, `location`, `client`) with Protocol-based decoupling between
`LocationEntry` and `Location`. Public API unchanged.

### Changed

- **`Location.case_sensitive`** is now a public read-only property (previously private
  `_case_sensitive`)

## [0.2.6] - 2026-04-04

Internal refactoring of the server REST API, the Rust client, and the Python client.
No wire-protocol changes; clients and server remain compatible with 0.2.5.

### Changed

- **Rust client** `FileBridgeClient::new()` and `with_timeout()` return `Result<Self, Error>`
  instead of `Result<Self, url::ParseError>`
- **Rust client** new error variants `Error::TokenRequired` and `Error::NonceMismatch` replace
  the generic `Error::Hmac` for non-HMAC failures
- **Server** missing `X-Nonce` header now returns 401 Unauthorized instead of 400 Bad Request

### Fixed

- **Python client** `FileBridgeReadStream` raises `FileBridgeError` instead of panicking when
  the stream decoder is not initialized

## [0.2.5] - 2026-04-03

### Added

- **CLI `list`** and **`info`** commands accept `--extensive` to include SHA-256 hashes
- **CLI `list`** now shows file type, human-readable size, and modification time; `--extensive`
  adds a hash column
- **CLI `info`** displays modification time in local timezone instead of UTC
- **Rust client** `list_extensive()` method for directory listings with SHA-256 hashes
- **Rust client** `with_timeout()` constructor and a default 30-second HTTP timeout
- **Python client** `timeout` parameter on `FileBridgeClient` (default 30 s)

### Fixed

- **Python client `list()`** in token mode now always sends the path in the encrypted body,
  fixing failures when listing the root directory with a token
- **Python client `glob()`** no longer passes `"."` as path to the server when called with no
  base path
- **Server** directory entries now include `mtime`; previously only files reported it

### Changed

- **Server** SHA-256 hash computation during extensive directory listings runs in parallel instead
  of sequentially

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
