use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub type_: String,
    pub nonce: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_credential: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    #[serde(rename = "type")]
    pub type_: String,
    pub nonce: String,
    pub signature: String,
    pub kid: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_serde_roundtrip() {
        let c = Challenge {
            type_: "agentpin-challenge".to_string(),
            nonce: "dGVzdC1ub25jZQ".to_string(),
            timestamp: "2026-01-30T00:00:00Z".to_string(),
            verifier_credential: Some("eyJ...".to_string()),
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: Challenge = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);

        // Verify "type" field name in JSON
        assert!(json.contains("\"type\":"));
    }

    #[test]
    fn test_response_serde_roundtrip() {
        let r = Response {
            type_: "agentpin-response".to_string(),
            nonce: "dGVzdC1ub25jZQ".to_string(),
            signature: "MEUCIQD...".to_string(),
            kid: "test-2026-01".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let r2: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(r, r2);
    }
}
