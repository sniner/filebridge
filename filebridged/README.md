# Filebridge Daemon (`filebridged`)

The server daemon (Rust/Axum) providing a secure, lightweight REST API for remote file access.

## Getting Started

### Configuration

Create a `config.toml` file to define your locations:

```toml
[[location]]
label = "demo"
path = "./demo_dir"
token = "your-secret-key"
allow_read = true
allow_create = true
# Optional: allow_replace, allow_delete, allow_recurse, allow_inspect
```

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

> **Note:** The cryptographic design has not been audited. Review the implementation before deploying in security-critical environments.
