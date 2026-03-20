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

# File ownership / permissions applied after every write (Unix only, all optional)
# file_owner and file_group accept a username/group name or a numeric UID/GID.
# file_mode is an octal string ("640" or "0640").
# file_owner = "appuser"
# file_group = "appgroup"
# file_mode  = "640"
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
{"name": "example.txt", "is_dir": false, "size": 1234, "mdate": "2026-01-01T12:00:00Z", "sha256": null}
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

## Request Body Limit

Encrypted request envelopes (`application/vnd.filebridge.request`) are limited to **64 KiB**. These are small JSON payloads (path + optional offset/length) that must be fully buffered in memory before decryption. Any envelope exceeding this size is rejected with `413 Payload Too Large`.

Streaming file transfers (`application/vnd.filebridge.stream`) are **not** subject to this limit. Data is written to disk chunk by chunk and never accumulates in server memory, so file size is bounded only by the filesystem.

---

> **Note:** The cryptographic design has not been audited. Review the implementation before deploying in security-critical environments.
