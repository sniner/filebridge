# Filebridge Daemon (`filebridged`)

The server daemon (Rust/Axum) providing a secure, lightweight REST API for remote file access.

## Getting Started

### Configuration

Create a `config.toml` file to define your locations:

```toml
[[location]]
label = "demo"
path = "./demo_dir"
token = "your-secret-key"   # optional; omit for open (unauthenticated) access

# Access control (all default to the value shown below)
allow_read    = true
allow_create  = true
allow_replace = false
allow_delete  = false
allow_inspect = true
allow_recurse = false
allow_mkdir   = false

# Ownership / permissions applied to newly written files and auto-created
# directories (Unix only, all optional).
# file_owner / file_group / dir_owner / dir_group accept a username/group
# name or a numeric UID/GID.
# file_mode / dir_mode are octal strings ("644" or "0644") — TOML has no
# native octal literal, so the value must be quoted.
#
# Fallback and defaults: if *any* of these six fields is set, dirs without an
# explicit dir_owner/dir_group fall back to file_owner/file_group, and the
# modes default to file_mode = 0644 and dir_mode = 0755. If none are set,
# no chmod/chown is performed.
# file_owner = "appuser"
# file_group = "appgroup"
# file_mode  = "644"
# dir_owner  = "appuser"   # defaults to file_owner if omitted
# dir_group  = "appgroup"  # defaults to file_group if omitted
# dir_mode   = "755"
```

Multiple `[[location]]` sections can be defined in the same file. Alternatively,
pass a **directory** as the config argument — all `*.toml` and `*.conf` files in
that directory are merged in alphabetical order:

```bash
filebridged --port 8000 /etc/filebridged/conf.d/
```

Unknown usernames or group names are treated as a startup error so that
misconfigured containers fail loudly instead of silently ignoring the setting.

### Running

```bash
cargo run -p filebridged -- config.toml
```

The server will listen on `0.0.0.0:8000` by default.

### Running as a systemd service

Example unit — save as `/etc/systemd/system/filebridged.service`:

```ini
[Unit]
Description=Filebridge Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/filebridged --port 8000 /usr/local/etc/filebridged.toml

Restart=always
RestartSec=5

# A file-serving daemon needs headroom above the systemd default soft
# limit of 1024 file descriptors.
LimitNOFILE=65536

# Run unprivileged; the account must be able to access the configured
# locations.
User=filebridge
Group=filebridge

# Optional hardening. With ProtectSystem=strict the filesystem is
# read-only for the service — list every writable location explicitly.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/srv/filebridge

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Then:

```bash
systemctl daemon-reload
systemctl enable --now filebridged
```

Note that `filebridged` does not crash on runtime errors such as fd
exhaustion, so `Restart=always` only covers actual crashes and OOM kills —
keep an eye on the journal for persistent error states.

## Security Modes

Filebridge operates in two distinct security modes depending on whether a `token` is configured for a given location.

### 1. Unencrypted / Open Mode

If no `token` is set in the configuration, the location is unprotected:
- **Use Case:** This mode is designed for use within secure, trusted private networks (e.g., behind a firewall or VPN) or for simple testing purposes.
- **Benefits:** It allows easy access using standard CLI tools like `curl` or `wget` without needing to handle signatures or encryption. For example, to download a file:
  ```bash
  curl -H "Accept: application/octet-stream" http://0.0.0.0:8000/demo/example.txt -o example.txt
  ```
- **Security:** Do not use this mode over the public internet. All data and metadata are transmitted in plaintext, offering no protection against interception or manipulation.

### 2. Token & AEAD Streaming Encryption Mode

When a `token` is configured for a location, Filebridge enforces strict authentication, integrity, and confidentiality measures:

- **Encrypted Metadata:** In token mode, the file path and parameters (offset, length) are **never exposed in the URL**. They are sent in an encrypted JSON body (`Content-Type: application/vnd.filebridge.request`), protected by ChaCha20Poly1305 AEAD. A network observer only sees the HTTP method and the location name — no file paths, no offsets.
- **Request Authentication:** Every request must include an `X-Timestamp` and an `X-Signature`. The signature is a hex-encoded HMAC-SHA256 hash calculated over the token, timestamp, HTTP method, and URI. Requests older than 5 minutes are rejected to prevent replay attacks.
- **Encrypted Streaming Payload:** File transfers (using `application/vnd.filebridge.stream`) protect the data payload:
  - **Chunked Transfer:** The data is transferred as a continuous stream broken down into discrete frames.
  - **AEAD Encryption:** The file payload is automatically encrypted using **ChaCha20Poly1305**. The symmetric key and nonce are derived via **HKDF-SHA256** from the token and the request's `X-Signature`, with separate derivation contexts for stream data and JSON responses.
  - **Chunk-by-Chunk Integrity:** Each encrypted chunk carries a native cryptographic authentication tag. Any tampered chunk is immediately detected and rejected during streaming without buffering the entire file.

---

## File Metadata and SHA-256 Hashing

A `GET` request to a file path without a streaming `Accept` header returns a JSON metadata object:

```json
{"name": "example.txt", "is_dir": false, "size": 1234, "mtime": "2026-01-01T12:00:00Z", "sha256": null}
```

To include the SHA-256 hash of the file, add the `extensive=true` query parameter (non-token mode) or set `"extensive": true` in the encrypted request envelope (token mode):

```bash
curl http://localhost:8000/api/v1/fs/demo/example.txt?extensive=true
```

The hash is computed server-side and **cached in memory**. The cache entry is invalidated automatically whenever the file's modification time or size changes, so repeated calls for unchanged files are cheap.

---

## Transport Security and TLS

`filebridged` does not implement TLS itself. This is a deliberate design decision.

**Why no built-in TLS:**
In **token mode**, all file payloads and metadata are end-to-end encrypted at the application layer using ChaCha20Poly1305 before they even reach the HTTP transport. A passive network observer sees only the HTTP method, the location name in the URL, and opaque ciphertext — no file paths, no content, no parameter values. Adding TLS on top would encrypt already-encrypted data.

Beyond that, TLS certificate management (provisioning, renewal, rotation) is orthogonal to the project's goal of being a lightweight file bridge. Reverse proxies handle this significantly better and are already part of most container-based deployments.

**When TLS is required nonetheless:**
If your policy requires TLS in transit (e.g. for compliance), or if you are using the unencrypted **open mode** over an untrusted network, run `filebridged` behind a TLS-terminating reverse proxy. Both the Rust and Python clients use `reqwest`/`httpx` and natively support HTTPS — just point the base URL at the proxy's HTTPS endpoint.

Minimal example using Caddy:
```caddyfile
filebridge.internal {
    reverse_proxy localhost:8000
}
```

## Request and Response Size Limits

### Client → Server (Request Bodies)

Encrypted request envelopes (`application/vnd.filebridge.request`) are limited to **64 KiB**. These are small JSON payloads (path + optional offset/length) that must be fully buffered in memory before decryption. Any envelope exceeding this size is rejected with `413 Payload Too Large`.

Streaming file uploads (`application/vnd.filebridge.stream`) are **not** subject to this limit. Data is written to disk chunk by chunk and never accumulates in server memory, so file size is bounded only by the filesystem.

### Server → Client (Response Bodies)

Responses — including directory listings and file metadata — are **not** subject to the 64 KiB envelope limit. In token mode, directory listings are serialized to JSON, compressed with zstd, encrypted, and returned as a single buffered response. There is no hard size cap; the practical limit is the server's available memory.

---

> **Note:** The cryptographic design has not been audited. Review the implementation before deploying in security-critical environments.
