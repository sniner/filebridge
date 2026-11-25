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

- `rustls` (default): rustls. It needs no TLS library on the system, so a
  program built with it runs regardless of the OpenSSL version installed, and
  it can be linked statically, as in a musl build.
- `native-tls`: the platform's TLS library, OpenSSL on Linux.

Both trust the system's certificate store, so a certificate from an internal CA
works with either. rustls is stricter: it speaks TLS 1.2 and 1.3 only, and it
requires the server's name among the certificate's subject alternative names.
For a server that does not meet this, use `native-tls`:

```toml
[dependencies]
filebridge = { version = "0.5", default-features = false, features = ["native-tls"] }
```

With neither feature, the client speaks plain `http://` only.

## Security: HMAC Signing

When a `token` is configured for a location, every request must include:
- `X-Timestamp`: Current Unix timestamp (UTC seconds).
- `X-Nonce`: Random hex string for replay protection.
- `X-Signature`: Hex-encoded HMAC-SHA256 signature.

The signature is calculated as:
`HEX(HMAC-SHA256(token, "filebridge-0.5\n" + timestamp + "\n" + nonce + "\n" + method + "\n" + path[?query]))`

A request whose timestamp differs from the server's clock by more than 30 seconds is rejected. Each nonce can only be used once.

**Automatic Encryption (AEAD):** When token authentication is used, the file payload is automatically encrypted using **ChaCha20Poly1305**. The cipher key and nonce are derived via **HKDF-SHA256** from the token and the `X-Signature` header, with separate derivation contexts for stream data and JSON responses. The AEAD cipher provides transparent confidentiality and chunk-wise integrity.

**Metadata Privacy:** In token mode, the file path and parameters (offset, length) are sent in an encrypted JSON body, not in the URL. The same body says whether a `GET` asks for the metadata or for the content of a file. Of a request, only the HTTP method and the location name are visible to a network observer.

**Encrypted Responses:** Every response to an authenticated request is encrypted and authenticated, including errors and the acknowledgement of a write, delete or rename. The HTTP status line always says `200`; the status of the operation is inside the encrypted body, and requests and responses are padded, so that an error, an acknowledgement and the metadata of a file have the same length. A file download remains recognisable by its size. Only a request that the server rejects before it is authenticated (wrong token, clocks too far apart, repeated nonce) is answered in plain text, and the clients report such an answer as unverified.

For the caller this means: `Error::Api` always carries the status and message that the server sent, and with a token both are verified. A verified response that does not fit the request, such as metadata where file content was asked for, is `Error::Protocol`. `Error::Unverified` is returned for every response that is not an encrypted one. Its status and text are what arrived and say nothing reliable about the operation, so do not treat `Error::Unverified(404, _)` as "the file does not exist". The usual causes are a wrong token, clocks more than 30 seconds apart, and a server older than 0.5.
