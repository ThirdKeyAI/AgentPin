//! gRPC metadata transport binding.
//!
//! Extracts and formats AgentPin credentials in gRPC metadata
//! via the `agentpin-credential` key.

use crate::error::Error;

/// The gRPC metadata key for AgentPin credentials.
pub const METADATA_KEY: &str = "agentpin-credential";

/// Extract the JWT from a gRPC metadata value.
///
/// Validates that the value is non-empty and returns it as the JWT string.
pub fn extract_credential(metadata_value: &str) -> Result<String, Error> {
    if metadata_value.is_empty() {
        return Err(Error::Transport(
            "Empty gRPC metadata value for agentpin-credential".into(),
        ));
    }

    Ok(metadata_value.to_string())
}

/// Format a JWT for use as a gRPC metadata value.
///
/// Returns the JWT string directly. The caller should attach it
/// to the `agentpin-credential` metadata key.
pub fn format_metadata_value(jwt: &str) -> String {
    jwt.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_valid_metadata() {
        let jwt = extract_credential("eyJ.payload.sig").unwrap();
        assert_eq!(jwt, "eyJ.payload.sig");
    }

    #[test]
    fn test_extract_empty_value() {
        assert!(extract_credential("").is_err());
    }

    #[test]
    fn test_metadata_key() {
        assert_eq!(METADATA_KEY, "agentpin-credential");
    }

    #[test]
    fn test_format_roundtrip() {
        let jwt = "eyJ.payload.sig";
        let value = format_metadata_value(jwt);
        let extracted = extract_credential(&value).unwrap();
        assert_eq!(extracted, jwt);
    }
}
