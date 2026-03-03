pub mod client;
pub mod error;
pub mod location;
pub mod models;
pub mod stream;

pub use client::FileBridgeClient;
pub use error::Error;
pub use location::FileBridgeLocation;
pub use models::Metadata;

pub type Result<T> = std::result::Result<T, Error>;
