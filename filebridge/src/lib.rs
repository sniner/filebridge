//! Async client library for the Filebridge REST API.
//!
//! Filebridge provides secure remote file access over HTTP, designed as a
//! lightweight alternative to SSHFS, SMB, or NFS — particularly for Docker
//! containers.
//!
//! # Quick start
//!
//! ```no_run
//! use filebridge::FileBridgeClient;
//!
//! # #[tokio::main]
//! # async fn main() -> filebridge::Result<()> {
//! let client = FileBridgeClient::new("http://localhost:8000")?;
//! let loc = client.location("my-share", None);
//!
//! // List directory contents
//! let entries = loc.list(None).await?;
//! for entry in &entries {
//!     println!("{} ({})", entry.name, if entry.is_dir { "dir" } else { "file" });
//! }
//!
//! // Read a file
//! let data = loc.read("hello.txt").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Authentication
//!
//! When a token is provided via [`FileBridgeClient::location`], requests are
//! HMAC-signed and file content is encrypted with ChaCha20-Poly1305. Without
//! a token, plain HTTP is used.
//!
//! ```no_run
//! # use filebridge::FileBridgeClient;
//! # let client = FileBridgeClient::new("http://localhost:8000").unwrap();
//! // Authenticated access with end-to-end encryption
//! let loc = client.location("my-share", Some("secret-token".into()));
//! ```

pub mod client;
pub mod error;
pub mod location;
pub mod models;
pub mod stream;

pub use client::FileBridgeClient;
pub use error::Error;
pub use location::FileBridgeLocation;
pub use models::Metadata;

/// A specialized [`Result`](std::result::Result) type for filebridge operations.
pub type Result<T> = std::result::Result<T, Error>;
