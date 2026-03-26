use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use moka::sync::Cache;

/// Maximum number of cached hash entries.
const MAX_CACHE_ENTRIES: u64 = 10_000;
/// Time-to-live for cache entries (1 hour).
const CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
struct HashCacheEntry {
    sha256: String,
    mtime: SystemTime,
    size: u64,
}

pub struct HashCache {
    entries: Cache<PathBuf, HashCacheEntry>,
}

impl HashCache {
    pub fn new() -> Self {
        Self {
            entries: Cache::builder()
                .max_capacity(MAX_CACHE_ENTRIES)
                .time_to_live(CACHE_TTL)
                .build(),
        }
    }

    pub fn invalidate(&self, path: &Path) {
        self.entries.invalidate(path);
    }

    pub async fn get_or_compute(&self, path: &Path) -> Result<String, std::io::Error> {
        let stat = tokio::fs::metadata(path).await?;
        let mtime = stat.modified()?;
        let size = stat.len();

        if let Some(entry) = self.entries.get(&path.to_path_buf())
            && entry.mtime == mtime
            && entry.size == size
        {
            return Ok(entry.sha256.clone());
        }

        // Cache miss or stale: recompute
        let hash = compute_sha256(path).await?;
        self.entries.insert(
            path.to_owned(),
            HashCacheEntry {
                sha256: hash.clone(),
                mtime,
                size,
            },
        );
        Ok(hash)
    }
}

async fn compute_sha256(path: &Path) -> Result<String, std::io::Error> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fbridge_cache_test_{tag}"))
    }

    /// SHA-256("hello") — well-known value, no newline
    const SHA256_HELLO: &str =
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[tokio::test]
    async fn test_sha256_known_value() {
        let path = temp_path("known");
        tokio::fs::write(&path, b"hello").await.unwrap();
        let hash = compute_sha256(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.ok();
        assert_eq!(hash, SHA256_HELLO);
    }

    #[tokio::test]
    async fn test_cache_returns_correct_hash() {
        let path = temp_path("correct");
        tokio::fs::write(&path, b"hello").await.unwrap();
        let cache = HashCache::new();
        let hash = cache.get_or_compute(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.ok();
        assert_eq!(hash, SHA256_HELLO);
    }

    #[tokio::test]
    async fn test_cache_hit_returns_same_value() {
        let path = temp_path("hit");
        tokio::fs::write(&path, b"hello").await.unwrap();
        let cache = HashCache::new();
        let h1 = cache.get_or_compute(&path).await.unwrap();
        let h2 = cache.get_or_compute(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.ok();
        assert_eq!(h1, h2);
        assert_eq!(h1, SHA256_HELLO);
    }

    #[tokio::test]
    async fn test_cache_invalidates_when_file_changes() {
        let path = temp_path("invalidate");
        // First write: 5 bytes
        tokio::fs::write(&path, b"hello").await.unwrap();
        let cache = HashCache::new();
        let h1 = cache.get_or_compute(&path).await.unwrap();
        assert_eq!(h1, SHA256_HELLO);

        // Second write: different content and different size → forces invalidation
        // even on filesystems with coarse mtime granularity
        tokio::fs::write(&path, b"hello world").await.unwrap();
        let h2 = cache.get_or_compute(&path).await.unwrap();
        tokio::fs::remove_file(&path).await.ok();

        assert_ne!(h1, h2);
    }
}
