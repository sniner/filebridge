# Changelog

This format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.10] - 2026-05-13

### Added

- **`allow_mkdir` location permission** (default `false`): when combined with `allow_create` and
  `allow_recurse`, PUT requests automatically create missing parent directories instead of failing
  with "path canonicalization failed". Permissions are checked in order: `allow_create` →
  `allow_recurse` → `allow_mkdir`. On Unix, newly created directories receive the location's
  `file_owner`/`file_group` (chown); `file_mode` is intentionally not applied to directories
  because a file mode like `0o644` would render them unenterable
- **HTTP `OPTIONS` on `/api/v1/fs/{dir_id}`** returns the permission set the server grants for a
  location as JSON: `{location, permissions: {read, create, replace, inspect, delete, recurse,
  mkdir}}`. In token mode the response is encrypted like every other JSON response
- **Rust `FileBridgeLocation::permissions()`** queries the new OPTIONS endpoint and returns a
  `Permissions` struct
- **Python `Location.permissions()`** returns a `Permissions` pydantic model

### Changed

- **Server PUT** lexically validates path components before joining them onto the location root;
  paths containing `..` or absolute segments are rejected with 403 rather than relying solely on
  `canonicalize()` (which can't catch escapes through not-yet-existing directories)

## [0.2.9] - 2026-04-11

### Added

- **MCP `glob_files` tool** matches files in a location against a glob pattern (`*`, `?`, `[seq]`,
  `**`); returns a compact `{path, is_dir, size}` listing by default, or full metadata with
  `detailed: true`. Results are capped at `max_results` and truncated rather than failing, so the
  model can refine its pattern based on the `truncated` flag in the response
- **`FILEBRIDGE_GLOB_MAX_RESULTS`** env var sets the default cap for `glob_files` (default 1024)

### Changed

- **Rust client `glob()`** future is now `Send`, allowing it to be awaited from `tokio::spawn`
  and other multi-thread executors

## [0.2.8] - 2026-04-08

### Added

- **Rust client `glob()`** method on `FileBridgeLocation` for matching remote files against
  glob patterns (`*`, `?`, `[seq]`, `**`); expansion happens client-side with segment-wise
  directory walking — no server changes required
- **CLI `get`** now accepts multiple targets and glob patterns
  (e.g. `get '/loc/*.txt' -o ./dest/`); a single match without `-o` still writes to stdout
- **CLI `get --force`** flag to overwrite existing local files; without it, existing files are
  skipped with a warning

### Changed

- **Python client `LocationProtocol`** now declares `list`, `glob`, `iterdir`, `walk` with
  concrete `Iterator[LocationEntry]` return types instead of `Iterator[Any]`

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
