# Changelog

This format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.4.2] - 2026-10-28

### Security

- **Dependencies**: the Rust client now requires `rand` 0.10.1 or newer, which fixes
  RUSTSEC-2026-0097: `rand::rng()` is unsound when a custom logger calls back into `rand`, a
  setup filebridge does not use. The `Cargo.lock` shipped with `filebridged`, `filebridge-cli`
  and `filebridge-mcp` moves to `rand` 0.10.3 and to `chacha20` 0.10.2; `chacha20` 0.10.0, which
  `rand` uses for its generator, has been yanked. No code changes

## [0.4.1] - 2026-10-28

### Added

- **TLS backend as a feature**: the Rust client takes its TLS library from a feature. `native-tls`,
  the default, keeps OpenSSL on Linux as before. `rustls` builds without OpenSSL, for static
  binaries such as musl builds: `default-features = false, features = ["rustls"]`. Both trust the
  system's certificate store, so a certificate from an internal CA works with either; rustls
  speaks TLS 1.2 and 1.3 only and requires the server's name among the certificate's subject
  alternative names. With neither feature the client speaks plain `http://` only

### Fixed

- **Signed request to a location without a token**: `filebridged` answered it in the clear, and
  a client holding a token for that location failed with a bare "nonce mismatch". It now refuses
  the request with `400` and "location has no token; send requests to it without one"

## [0.4.0] - 2026-08-08

### Added

- **Rename**: files can now be renamed and moved within a location. `filebridged` accepts
  `POST /api/v1/fs/{location}/{path}?target={newpath}`; token-mode clients send both paths in the
  encrypted envelope instead, so neither appears in the URL. The Rust client gains
  `FileBridgeLocation::rename(from, to)`, the Python client `Location.rename(src, dst)`. This is
  the missing piece for write-then-publish patterns: write to a temporary name, then rename, and
  readers never observe a half-written file
- **Rename permissions**: a rename requires both `allow_create` and `allow_delete` on the
  location — there is no separate `allow_rename` flag, so existing configurations need no change.
  Replacing an existing target additionally requires `allow_replace`, which keeps a create-only
  location from being overwritten through a rename. Only regular files can be renamed;
  directories are rejected

### Fixed

- **`filebridged` leaked file paths in error responses**: a request for a path that could not be
  resolved echoed that path back in the error body. For token-protected locations this undid the
  metadata confidentiality of token mode, where the path is deliberately carried in an encrypted
  envelope so it never appears in the clear. Error responses no longer contain the requested
  path; operators still get it from the daemon's per-request log line

### Known limitations

- **Error responses are not covered by token-mode protection.** The leak fixed above was one
  instance of this; the broader gap is understood and scheduled for a later release, which will
  require updating server and clients together. Until then, run token-protected locations behind
  TLS — that is the recommended deployment in any case

### Compatibility

- The new endpoint is purely additive. Existing clients are unaffected, and a 0.4 client talking
  to an older server gets a `405` for `rename` only — every other operation keeps working

### Fixed

- **`filebridged` fd exhaustion on large directories**: extensive listings hashed every file in
  the directory concurrently, so a directory with more files than the process fd limit drove the
  daemon into a permanent `EMFILE` error state (hash failures, eventually `accept` errors) that
  only a restart could clear. Hashing is now capped at 32 concurrently open files, independent of
  directory size. Deployments are still advised to set `LimitNOFILE=65536` (or similar) in their
  systemd unit — the systemd default soft limit of 1024 fds is tight for a file-serving daemon
- **`filebridged` warning flood**: failed hash computations during a listing are now reported as
  one summary warning per listing instead of one warning per file, so a persistent error state no
  longer floods the journal

### Changed

- **`filebridged` TCP keepalive**: the listener now enables TCP keepalive (60 s idle, 15 s probe
  interval), so half-open connections from vanished clients are reaped by the kernel instead of
  holding their file descriptors indefinitely

## [0.3.0] - 2026-06-10

### Breaking changes

- **Token-mode wire format**: encrypted request envelopes (client → server) and encrypted JSON
  responses (server → client) now use direction-separated encryption keys and nonces. 0.2.x
  clients cannot talk to 0.3.0 servers in token mode and vice versa — update server, Rust client,
  and Python client together. Locations without a token are unaffected
- **Rust `stream` module**: `encrypt_json_response`/`decrypt_json_response` are now
  `encrypt_json`/`decrypt_json` and take a `JsonDirection` (`Request` or `Response`). The Python
  equivalents take a `direction` literal (`"request"`/`"response"`)

### Fixed

- **Nonce reuse in token mode**: the request envelope and the JSON response of the same request
  were encrypted under the same ChaCha20-Poly1305 key *and* nonce, weakening both confidentiality
  (keystream reuse) and authenticity (Poly1305 tag forgery) of metadata operations such as `info`,
  `list`, and directory reads. File content streams were not affected. Fixed by the
  direction-separated key derivation above
- **Plaintext downgrade in token mode**: the `Accept` header is not covered by the request
  signature, yet the server answered `Accept: application/octet-stream` with unencrypted file
  content even for token-protected locations, and both clients accepted responses with unexpected
  content types as file data without verification. The server now always answers token-mode file
  reads with the encrypted stream format, and both clients reject anything else
- **Python `Location.open(path, "w")` never truncated**: buffered writes always sent an explicit
  offset, so overwriting an existing longer file left the old tail in place. The first flush now
  omits the offset (server truncates), and closing a handle without writes creates/truncates the
  file like a local `open(..., "w")`
- **Python `FileBridgeReadStream`**: an empty HTTP chunk is no longer misreported as end-of-file
  to `RawIOBase` consumers such as `TextIOWrapper`
- **Python read responses**: unexpected JSON metadata where file content was requested now raises
  `FileBridgeError` instead of being returned verbatim as file bytes (matching the Rust client)

## [0.2.15] - 2026-06-09

### Fixed

- **`filebridged` replay cache**: the request signature is now verified before a nonce is recorded.
  Previously any request with a fresh nonce and a valid timestamp consumed a cache slot regardless
  of whether its signature checked out, so an unauthenticated client could flood the nonce cache and
  trigger server-wide `429 Too Many Requests` for legitimate callers
- **`filebridged` replay window**: seen nonces are now retained for the full timestamp acceptance
  window (twice the clock-skew tolerance). Previously a captured request stayed replayable for a
  short period after its nonce expired but before its timestamp did
- **stream decoding**: a single stream frame is now capped at 1 MiB. Previously a malicious or
  corrupt 32-bit length field could make the receiver buffer up to 4 GiB before the frame completed

## [0.2.14] - 2026-05-21

### Changed

- **`filebridged` graceful shutdown**: the daemon now reacts to `SIGINT` and `SIGTERM` by closing
  the listener (new connections see `ECONNREFUSED`) and draining in-flight requests before
  exiting. Previously both signals were ignored, so Docker had to follow up with `SIGKILL` after
  the stop timeout

## [0.2.13] - 2026-05-18

### Added

- **`dir_owner` / `dir_group` / `dir_mode` location config** (Unix only): controls ownership and
  mode applied to directories auto-created via `allow_mkdir`. If `dir_owner`/`dir_group` are
  omitted they fall back to `file_owner`/`file_group`. `dir_mode` is an octal string ("755" or
  "0755"), same convention as `file_mode`

### Fixed

- **Python client `Location.glob()` / `Location.walk()`**: a leading `/` in the glob pattern or
  walk start path is now treated as relative to the location root instead of being matched as a
  literal path component. Previously `loc.glob("/feedback/*.xml")` listed only the location root
  and returned nothing; only the slashless form `loc.glob("feedback/*.xml")` worked

### Changed

- **Default modes when any permission field is configured**: `file_mode` defaults to `0644` and
  `dir_mode` defaults to `0755` when at least one of `file_owner`/`file_group`/`file_mode`/
  `dir_owner`/`dir_group`/`dir_mode` is set. Locations with no permission config remain
  untouched (no chmod/chown). Previously `file_mode` had no default and auto-created directories
  never had their mode set
- **README** now documents `allow_mkdir` and the new `dir_*` fields

## [0.2.12] - 2026-05-13

### Added

- **MCP `query_files` tool** combines filtering, sorting, and limiting in a single call —
  the LLM-friendly alternative to listing and post-processing. Supports `pattern` (glob,
  overrides `path` and matches recursively), `kind` (`file`/`dir`/`any`), `min_size`/`max_size`,
  `modified_after`/`modified_before` (ISO date or RFC 3339 timestamp), `sort_by`
  (`name`/`size`/`mtime`), `order` (`asc`/`desc`), and `limit`. All filters are AND-combined.
  Entries with missing sort keys sort last regardless of order. Returns
  `{matches, count, total, truncated}` like `glob_files`

## [0.2.11] - 2026-05-13

### Changed

- **Server location config**: TOML field renamed from `label` to `name`. The old `label` key is
  accepted as a serde alias for backward compatibility; deployments can migrate at their own pace.
  The alias is intended to be removed in a future 0.3.x release
- **MCP location config (BREAKING)**: TOML fields restructured to `name` (server-side identifier,
  required) and `alias` (MCP-local shortcut, optional, defaults to `name`). Previously
  `name` was the MCP-local field and `location_id` the optional server-side override
- **MCP environment variables (BREAKING)**: `FILEBRIDGE_LOCATION` → `FILEBRIDGE_LOCATION_NAME`,
  `FILEBRIDGE_LOCATION_ID` → `FILEBRIDGE_LOCATION_ALIAS`

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
