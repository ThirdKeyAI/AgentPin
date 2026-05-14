//! WebSocket transport binding.
//!
//! Extracts and formats AgentPin credentials in JSON auth messages
//! of the form `{"type":"agentpin-auth","credential":"<JWT>"}`.

use crate::error::Error;

const AUTH_TYPE: &str = "agentpin-auth";

/// Extract the JWT from a WebSocket JSON auth message.
///
/// Expects `{"type":"agentpin-auth","credential":"<JWT>"}`.
pub fn extract_credential(message: &str) -> Result<String, Error> {
    let parsed: serde_json::Value = serde_json::from_str(message)
        .map_err(|e| Error::Transport(format!("Invalid JSON: {}", e)))?;

    let msg_type = parsed
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Transport("Missing or non-string 'type' field".into()))?;

    if msg_type != AUTH_TYPE {
        return Err(Error::Transport(format!(
            "Expected type '{}', got '{}'",
            AUTH_TYPE, msg_type
        )));
    }

    parsed
        .get("credential")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Transport("Missing or non-string 'credential' field".into()))
}

/// Format a JWT as a WebSocket auth message JSON string.
///
/// Returns `{"type":"agentpin-auth","credential":"<jwt>"}`.
pub fn format_auth_message(jwt: &str) -> String {
    serde_json::json!({
        "type": AUTH_TYPE,
        "credential": jwt,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_valid_message() {
        let msg = r#"{"type":"agentpin-auth","credential":"eyJ.payload.sig"}"#;
        let jwt = extract_credential(msg).unwrap();
        assert_eq!(jwt, "eyJ.payload.sig");
    }

    #[test]
    fn test_extract_wrong_type() {
        let msg = r#"{"type":"other-auth","credential":"eyJ.payload.sig"}"#;
        assert!(extract_credential(msg).is_err());
    }

    #[test]
    fn test_extract_missing_credential() {
        let msg = r#"{"type":"agentpin-auth"}"#;
        assert!(extract_credential(msg).is_err());
    }

    #[test]
    fn test_format_roundtrip() {
        let jwt = "eyJ.payload.sig";
        let msg = format_auth_message(jwt);
        let extracted = extract_credential(&msg).unwrap();
        assert_eq!(extracted, jwt);
    }
}
