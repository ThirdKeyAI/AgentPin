use std::collections::HashMap;

use chrono::Utc;

use crate::error::{Error, ErrorCode};
use crate::jwk::{jwk_thumbprint, Jwk};
use crate::types::pinning::{PinnedDomain, PinnedKey, TrustLevel};

/// Result of checking a key against the pin store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinningResult {
    /// First time seeing this domain — key has been pinned.
    FirstUse,
    /// Domain seen before and key matches a pinned key.
    Matched,
    /// Domain seen before but key does NOT match any pinned key.
    Changed,
}

/// In-memory TOFU key pinning store.
#[derive(Debug, Clone, Default)]
pub struct KeyPinStore {
    domains: HashMap<String, PinnedDomain>,
}

/// Pin-store key for a domain: the normalized hostname when valid, the raw
/// string otherwise (AP-3).
fn pin_key(domain: &str) -> String {
    crate::domain::normalize_domain(domain).unwrap_or_else(|_| domain.to_string())
}

impl KeyPinStore {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    /// Check a key against the pin store. If this is the first time seeing
    /// the domain, the key is pinned (TOFU). Returns the pinning result.
    pub fn check_and_pin(&mut self, domain: &str, jwk: &Jwk) -> PinningResult {
        let domain = &pin_key(domain);
        let key_hash = jwk_thumbprint(jwk);
        let now = Utc::now().to_rfc3339();

        if let Some(pinned) = self.domains.get_mut(domain) {
            // Domain previously seen — check if key matches
            if let Some(pk) = pinned
                .pinned_keys
                .iter_mut()
                .find(|pk| pk.public_key_hash == key_hash)
            {
                pk.last_seen = now;
                PinningResult::Matched
            } else {
                PinningResult::Changed
            }
        } else {
            // First time seeing this domain — TOFU pin
            self.domains.insert(
                domain.to_string(),
                PinnedDomain {
                    domain: domain.to_string(),
                    pinned_keys: vec![PinnedKey {
                        kid: jwk.kid.clone(),
                        public_key_hash: key_hash,
                        first_seen: now.clone(),
                        last_seen: now,
                        trust_level: TrustLevel::Tofu,
                    }],
                },
            );
            PinningResult::FirstUse
        }
    }

    /// Add a key to an existing domain's pin set (e.g., during key rotation).
    pub fn add_key(&mut self, domain: &str, jwk: &Jwk) {
        let domain = &pin_key(domain);
        let key_hash = jwk_thumbprint(jwk);
        let now = Utc::now().to_rfc3339();

        let pinned = self
            .domains
            .entry(domain.to_string())
            .or_insert_with(|| PinnedDomain {
                domain: domain.to_string(),
                pinned_keys: vec![],
            });

        if !pinned
            .pinned_keys
            .iter()
            .any(|pk| pk.public_key_hash == key_hash)
        {
            pinned.pinned_keys.push(PinnedKey {
                kid: jwk.kid.clone(),
                public_key_hash: key_hash,
                first_seen: now.clone(),
                last_seen: now,
                trust_level: TrustLevel::Tofu,
            });
        }
    }

    /// Get pinned domain info.
    pub fn get_domain(&self, domain: &str) -> Option<&PinnedDomain> {
        self.domains.get(&pin_key(domain))
    }

    /// Serialize the store to JSON.
    pub fn to_json(&self) -> Result<String, Error> {
        let domains: Vec<&PinnedDomain> = self.domains.values().collect();
        Ok(serde_json::to_string_pretty(&domains)?)
    }

    /// Deserialize the store from JSON.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let domains: Vec<PinnedDomain> = serde_json::from_str(json)?;
        let mut map: HashMap<String, PinnedDomain> = HashMap::new();
        for mut d in domains {
            let key = pin_key(&d.domain);
            d.domain = key.clone();
            // Merge duplicate entries that differ only by case into one pin set.
            match map.get_mut(&key) {
                Some(existing) => {
                    for pk in d.pinned_keys {
                        if !existing
                            .pinned_keys
                            .iter()
                            .any(|e| e.public_key_hash == pk.public_key_hash)
                        {
                            existing.pinned_keys.push(pk);
                        }
                    }
                }
                None => {
                    map.insert(key, d);
                }
            }
        }
        Ok(Self { domains: map })
    }
}

/// Check pinning and return an error if key has changed (for use in verification flow).
pub fn check_pinning(
    store: &mut KeyPinStore,
    domain: &str,
    jwk: &Jwk,
) -> Result<PinningResult, Error> {
    let result = store.check_and_pin(domain, jwk);
    if result == PinningResult::Changed {
        return Err(Error::Verification {
            code: ErrorCode::KeyPinMismatch,
            message: format!(
                "Key for domain '{}' has changed since last pinned (kid: '{}')",
                domain, jwk.kid
            ),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_jwk(kid: &str, x: &str) -> Jwk {
        Jwk {
            kid: kid.to_string(),
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: x.to_string(),
            y: "test-y".to_string(),
            use_: "sig".to_string(),
            key_ops: None,
            exp: None,
        }
    }

    #[test]
    fn test_first_use_pins_key() {
        let mut store = KeyPinStore::new();
        let jwk = make_test_jwk("key-1", "x-value-1");
        let result = store.check_and_pin("example.com", &jwk);
        assert_eq!(result, PinningResult::FirstUse);

        // Second time should match
        let result = store.check_and_pin("example.com", &jwk);
        assert_eq!(result, PinningResult::Matched);
    }

    #[test]
    fn test_key_change_detected() {
        let mut store = KeyPinStore::new();
        let jwk1 = make_test_jwk("key-1", "x-value-1");
        store.check_and_pin("example.com", &jwk1);

        let jwk2 = make_test_jwk("key-2", "x-value-2");
        let result = store.check_and_pin("example.com", &jwk2);
        assert_eq!(result, PinningResult::Changed);
    }

    #[test]
    fn test_add_key_allows_rotation() {
        let mut store = KeyPinStore::new();
        let jwk1 = make_test_jwk("key-1", "x-value-1");
        store.check_and_pin("example.com", &jwk1);

        let jwk2 = make_test_jwk("key-2", "x-value-2");
        store.add_key("example.com", &jwk2);

        // Both keys should now match
        assert_eq!(
            store.check_and_pin("example.com", &jwk1),
            PinningResult::Matched
        );
        assert_eq!(
            store.check_and_pin("example.com", &jwk2),
            PinningResult::Matched
        );
    }

    #[test]
    fn test_json_roundtrip() {
        let mut store = KeyPinStore::new();
        let jwk = make_test_jwk("key-1", "x-value-1");
        store.check_and_pin("example.com", &jwk);

        let json = store.to_json().unwrap();
        let store2 = KeyPinStore::from_json(&json).unwrap();

        assert!(store2.get_domain("example.com").is_some());
        assert_eq!(
            store2.get_domain("example.com").unwrap().pinned_keys.len(),
            1
        );
    }

    #[test]
    fn test_check_pinning_error_on_change() {
        let mut store = KeyPinStore::new();
        let jwk1 = make_test_jwk("key-1", "x-value-1");
        store.check_and_pin("example.com", &jwk1);

        let jwk2 = make_test_jwk("key-2", "x-value-2");
        let result = check_pinning(&mut store, "example.com", &jwk2);
        assert!(result.is_err());
    }

    /// AP-3: pins are keyed on the normalized domain, so case variants and
    /// trailing dots share one pin set.
    #[test]
    fn test_pin_key_normalized() {
        let mut store = KeyPinStore::new();
        let jwk1 = make_test_jwk("key-1", "x-value-1");
        let jwk2 = make_test_jwk("key-2", "x-value-2");
        assert_eq!(
            store.check_and_pin("example.com", &jwk1),
            PinningResult::FirstUse
        );
        assert_eq!(
            store.check_and_pin("EXAMPLE.COM", &jwk1),
            PinningResult::Matched
        );
        assert_eq!(
            store.check_and_pin("Example.Com.", &jwk2),
            PinningResult::Changed
        );
        assert!(store.get_domain("EXAMPLE.COM").is_some());

        // Persisted stores with mixed-case entries are merged on load.
        let json = r#"[{"domain":"EXAMPLE.COM","pinned_keys":[{"kid":"k","public_key_hash":"h1","first_seen":"t","last_seen":"t","trust_level":"tofu"}]},
                       {"domain":"example.com","pinned_keys":[{"kid":"k2","public_key_hash":"h2","first_seen":"t","last_seen":"t","trust_level":"tofu"}]}]"#;
        let loaded = KeyPinStore::from_json(json).unwrap();
        assert_eq!(
            loaded.get_domain("example.com").unwrap().pinned_keys.len(),
            2
        );
    }

    #[test]
    fn test_different_domains_independent() {
        let mut store = KeyPinStore::new();
        let jwk1 = make_test_jwk("key-1", "x-value-1");
        let jwk2 = make_test_jwk("key-2", "x-value-2");

        store.check_and_pin("a.com", &jwk1);
        store.check_and_pin("b.com", &jwk2);

        assert_eq!(store.check_and_pin("a.com", &jwk1), PinningResult::Matched);
        assert_eq!(store.check_and_pin("b.com", &jwk2), PinningResult::Matched);
        // Cross-domain should fail
        assert_eq!(store.check_and_pin("a.com", &jwk2), PinningResult::Changed);
    }
}
