# Filebridge Library

A high-level Rust library for interacting with the Filebridge daemon (`filebridged`).

## Getting Started

Add the library to your `Cargo.toml`:

```toml
[dependencies]
filebridge = { path = "../filebridge" } # adjust path as needed
```

### Usage Example

```rust
use filebridge::FileBridgeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = FileBridgeClient::new("http://localhost:8000")?;
    let loc = client.location("demo", Some("your-secret-key".into()));

    // Write a file
    loc.write("hello.txt", b"Hello World!", None).await?;

    // Read a specific chunk
    let data = loc.read("hello.txt", Some(6), Some(5)).await?;
    println!("Chunk: {}", String::from_utf8_lossy(&data)); // prints "World"
    Ok(())
}
```

## Security: HMAC Signing

When a `token` is configured for a location, every request must include:
- `X-Timestamp`: Current Unix timestamp (UTC seconds).
- `X-Signature`: Hex-encoded HMAC-SHA256 signature.

The signature is calculated as:
`HEX(HMAC-SHA256(token, timestamp + method + full_uri))`

Requests older than 300 seconds (5 minutes) are automatically rejected to prevent replay attacks.

**Automatic Encryption (AEAD):** When token authentication is used, the file payload is automatically encrypted using **ChaCha20Poly1305**. The cipher key and nonce are derived via **HKDF-SHA256** from the token and the `X-Signature` header, with separate derivation contexts for stream data and JSON responses. The AEAD cipher provides transparent confidentiality and chunk-wise integrity.

**Metadata Privacy:** In token mode, the file path and parameters (offset, length) are sent in an encrypted JSON body, not in the URL. Only the HTTP method and the location name are visible to a network observer.
