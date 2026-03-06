use axum::http::StatusCode;
use moka::sync::Cache;
use std::time::Duration;

pub struct NonceValidator {
    cache: Cache<String, ()>,
}

impl Default for NonceValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceValidator {
    pub fn new() -> Self {
        let cache = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(30))
            .build();
        Self { cache }
    }

    pub fn is_replay(&self, nonce: &str) -> Result<bool, StatusCode> {
        // Evaluate cache capacity
        // If entry_count is close to 100k (e.g., > 95_000), we return 429 to be safe before we evict keys
        // NOTE: Moka's entry_count might be slightly delayed, but it is good enough for flood protection
        if self.cache.entry_count() > 95_000 {
            tracing::warn!(
                "Nonce cache is near full capacity! Rejecting requests to prevent eviction attacks."
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        let entry = self.cache.entry_by_ref(nonce).or_insert(());
        Ok(!entry.is_fresh())
    }
}
