use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedDomain {
    pub domain: String,
    pub pinned_keys: Vec<PinnedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedKey {
    pub kid: String,
    pub public_key_hash: String,
    pub first_seen: String,
    pub last_seen: String,
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Tofu,
    Verified,
    Pinned,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pinned_domain_serde_roundtrip() {
        let pd = PinnedDomain {
            domain: "example.com".to_string(),
            pinned_keys: vec![PinnedKey {
                kid: "example-2026-01".to_string(),
                public_key_hash: "abcdef1234567890".to_string(),
                first_seen: "2026-01-15T00:00:00Z".to_string(),
                last_seen: "2026-01-30T00:00:00Z".to_string(),
                trust_level: TrustLevel::Tofu,
            }],
        };
        let json = serde_json::to_string(&pd).unwrap();
        let pd2: PinnedDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(pd, pd2);
    }

    #[test]
    fn test_trust_level_serde() {
        assert_eq!(
            serde_json::to_string(&TrustLevel::Tofu).unwrap(),
            "\"tofu\""
        );
        assert_eq!(
            serde_json::to_string(&TrustLevel::Verified).unwrap(),
            "\"verified\""
        );
        assert_eq!(
            serde_json::to_string(&TrustLevel::Pinned).unwrap(),
            "\"pinned\""
        );
    }
}
