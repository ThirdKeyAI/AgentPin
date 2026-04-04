use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::Error;

/// Trait for nonce deduplication stores.
pub trait NonceStore: Send + Sync {
    /// Check if a nonce has been seen before. If not, record it with the given TTL.
    /// Returns `Ok(true)` if the nonce is fresh (not seen before).
    /// Returns `Ok(false)` if the nonce has already been used (replay).
    fn check_and_record(&self, nonce: &str, ttl: Duration) -> Result<bool, Error>;
}

/// In-memory nonce store with lazy expiry cleanup.
pub struct InMemoryNonceStore {
    entries: Mutex<HashMap<String, Instant>>,
}

impl InMemoryNonceStore {
    /// Create a new empty nonce store.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceStore for InMemoryNonceStore {
    fn check_and_record(&self, nonce: &str, ttl: Duration) -> Result<bool, Error> {
        let mut map = self
            .entries
            .lock()
            .map_err(|e| Error::Jwt(format!("Nonce store lock poisoned: {}", e)))?;

        let now = Instant::now();

        // Lazy cleanup: remove all expired entries.
        map.retain(|_, expiry| *expiry > now);

        // Check if the nonce is already present (and not expired, since we just cleaned).
        if map.contains_key(nonce) {
            return Ok(false);
        }

        // Record the nonce with its expiry.
        map.insert(nonce.to_string(), now + ttl);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_nonce_accepted() {
        let store = InMemoryNonceStore::new();
        let result = store
            .check_and_record("nonce-1", Duration::from_secs(60))
            .unwrap();
        assert!(result, "First use of a nonce should return true");
    }

    #[test]
    fn test_duplicate_nonce_rejected() {
        let store = InMemoryNonceStore::new();
        let ttl = Duration::from_secs(60);
        store.check_and_record("nonce-dup", ttl).unwrap();
        let result = store.check_and_record("nonce-dup", ttl).unwrap();
        assert!(!result, "Second use of the same nonce should return false");
    }

    #[test]
    fn test_expired_nonce_reusable() {
        let store = InMemoryNonceStore::new();
        let ttl = Duration::from_millis(1);
        store.check_and_record("nonce-exp", ttl).unwrap();

        std::thread::sleep(Duration::from_millis(10));

        let result = store.check_and_record("nonce-exp", ttl).unwrap();
        assert!(result, "Expired nonce should be accepted again");
    }

    #[test]
    fn test_concurrent_safety() {
        let store = InMemoryNonceStore::new();
        let ttl = Duration::from_secs(60);

        let first = store.check_and_record("nonce-cc", ttl).unwrap();
        assert!(first);

        let second = store.check_and_record("nonce-cc", ttl).unwrap();
        assert!(!second);
    }
}
