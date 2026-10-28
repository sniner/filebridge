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

    // Read entire file
    let data = loc.read("hello.txt").await?;

    // Read a specific byte range
    let chunk = loc.read_range("hello.txt", 6, 5).await?;
    println!("Chunk: {}", String::from_utf8_lossy(&chunk)); // prints "World"

    // File metadata (name, size, mtime)
    let meta = loc.info("hello.txt").await?;
    println!("Size: {:?}", meta.size);

    // Extended metadata including SHA-256 hash (computed and cached server-side)
    let meta = loc.info_extensive("hello.txt").await?;
    println!("SHA-256: {:?}", meta.sha256);

    // List directory contents
    let entries = loc.list(None).await?;
    for entry in &entries {
        println!("{} ({})", entry.name, if entry.is_dir { "dir" } else { "file" });
    }

    // Rename/move within the location. Writing to a temporary name and renaming
    // it into place keeps a concurrent reader from seeing a half-written file.
    loc.rename("hello.txt", "greeting.txt").await?;

    // Delete a file
    loc.delete("greeting.txt").await?;

    Ok(())
}
```

### Streaming

For large files, streaming methods avoid buffering the entire content in memory:

```rust
use tokio::fs::File;
use tokio::io::BufReader;

// Stream a file to the server
let file = File::open("large-file.bin").await?;
loc.write_stream("large-file.bin", BufReader::new(file)).await?;

// Stream a file from the server
let mut out = File::create("downloaded.bin").await?;
loc.read_stream("large-file.bin", &mut out).await?;
```

## TLS

For `https://` servers the client needs a TLS backend, chosen by a feature:

- `native-tls` (default): the platform's TLS library, OpenSSL on Linux.
- `rustls`: rustls, without OpenSSL, for static builds such as musl binaries.

Both trust the system's certificate store, so a certificate from an internal CA
works with either. rustls is stricter: it speaks TLS 1.2 and 1.3 only, and it
requires the server's name among the certificate's subject alternative names.

```toml
[dependencies]
filebridge = { version = "0.4.1", default-features = false, features = ["rustls"] }
```

With neither feature, the client speaks plain `http://` only.

## Security: HMAC Signing

When a `token` is configured for a location, every request must include:
- `X-Timestamp`: Current Unix timestamp (UTC seconds).
- `X-Nonce`: Random hex string for replay protection.
- `X-Signature`: Hex-encoded HMAC-SHA256 signature.

The signature is calculated as:
`HEX(HMAC-SHA256(token, timestamp + nonce + method + path[?query]))`

Requests older than 300 seconds (5 minutes) are automatically rejected. Each nonce can only be used once.

**Automatic Encryption (AEAD):** When token authentication is used, the file payload is automatically encrypted using **ChaCha20Poly1305**. The cipher key and nonce are derived via **HKDF-SHA256** from the token and the `X-Signature` header, with separate derivation contexts for stream data and JSON responses. The AEAD cipher provides transparent confidentiality and chunk-wise integrity.

**Metadata Privacy:** In token mode, the file path and parameters (offset, length) are sent in an encrypted JSON body, not in the URL. Only the HTTP method and the location name are visible to a network observer.
