//! MCP (Model Context Protocol) transport binding.
//!
//! Extracts and formats AgentPin credentials in MCP message metadata
//! via the `agentpin_credential` field.

use crate::error::Error;

const FIELD_NAME: &str = "agentpin_credential";

/// Extract the JWT from an MCP metadata JSON value.
///
/// Expects `meta["agentpin_credential"]` to be a string containing the JWT.
pub fn extract_credential(meta: &serde_json::Value) -> Result<String, Error> {
    let field = meta.get(FIELD_NAME).ok_or_else(|| {
        Error::Transport(format!("Missing '{}' field in MCP metadata", FIELD_NAME))
    })?;

    field
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Transport(format!("'{}' field is not a string", FIELD_NAME)))
}

/// Format a JWT as an MCP metadata JSON value.
///
/// Returns `{"agentpin_credential": "<jwt>"}`.
pub fn format_meta_field(jwt: &str) -> serde_json::Value {
    serde_json::json!({ FIELD_NAME: jwt })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_valid_meta() {
        let meta = serde_json::json!({ "agentpin_credential": "eyJ.payload.sig" });
        let jwt = extract_credential(&meta).unwrap();
        assert_eq!(jwt, "eyJ.payload.sig");
    }

    #[test]
    fn test_extract_missing_field() {
        let meta = serde_json::json!({ "other_field": "value" });
        assert!(extract_credential(&meta).is_err());
    }

    #[test]
    fn test_extract_wrong_type() {
        let meta = serde_json::json!({ "agentpin_credential": 42 });
        assert!(extract_credential(&meta).is_err());
    }

    #[test]
    fn test_format_roundtrip() {
        let jwt = "eyJ.payload.sig";
        let meta = format_meta_field(jwt);
        let extracted = extract_credential(&meta).unwrap();
        assert_eq!(extracted, jwt);
    }
}
