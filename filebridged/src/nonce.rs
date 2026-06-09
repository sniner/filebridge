use crate::auth::MAX_TIMESTAMP_SKEW_SECS;
use crate::error::ApiError;
use moka::sync::Cache;
use std::time::Duration;

/// How long a seen nonce is remembered. A request timestamp `T` is accepted
/// while the clock is in `[T - skew, T + skew]`, so the same request can be
/// presented anywhere in a `2 * skew`-wide window. The nonce must be retained
/// for at least that full window, otherwise it could expire while the timestamp
/// is still valid and the request would become replayable.
pub const NONCE_TTL_SECS: u64 = 2 * MAX_TIMESTAMP_SKEW_SECS;

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
            .time_to_live(Duration::from_secs(NONCE_TTL_SECS))
            .build();
        Self { cache }
    }

    pub fn is_replay(&self, nonce: &str) -> Result<bool, ApiError> {
        // Evaluate cache capacity
        // If entry_count is close to 100k (e.g., > 95_000), we return 429 to be safe before we evict keys
        // NOTE: Moka's entry_count might be slightly delayed, but it is good enough for flood protection
        if self.cache.entry_count() > 95_000 {
            tracing::warn!(
                "Nonce cache is near full capacity! Rejecting requests to prevent eviction attacks."
            );
            return Err(ApiError::TooManyRequests);
        }

        let entry = self.cache.entry_by_ref(nonce).or_insert(());
        Ok(!entry.is_fresh())
    }
}
