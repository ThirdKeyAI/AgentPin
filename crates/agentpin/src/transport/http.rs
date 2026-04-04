//! HTTP header transport binding.
//!
//! Extracts and formats AgentPin credentials in `Authorization: AgentPin <JWT>` headers.

use crate::error::Error;

const PREFIX: &str = "AgentPin ";

/// Extract the JWT from an `Authorization` header value.
///
/// Expects the format `AgentPin <JWT>`. Returns the raw JWT string.
pub fn extract_credential(header_value: &str) -> Result<String, Error> {
    let jwt = header_value.strip_prefix(PREFIX).ok_or_else(|| {
        Error::Transport("Missing 'AgentPin ' prefix in Authorization header".into())
    })?;

    if jwt.is_empty() {
        return Err(Error::Transport(
            "Empty credential in Authorization header".into(),
        ));
    }

    Ok(jwt.to_string())
}

/// Format a JWT for use in an `Authorization` header.
///
/// Returns `"AgentPin <jwt>"`.
pub fn format_authorization_header(jwt: &str) -> String {
    format!("AgentPin {}", jwt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_valid_header() {
        let jwt = extract_credential("AgentPin eyJhbGciOiJFUzI1NiJ9.payload.sig").unwrap();
        assert_eq!(jwt, "eyJhbGciOiJFUzI1NiJ9.payload.sig");
    }

    #[test]
    fn test_extract_missing_prefix() {
        let err = extract_credential("Bearer eyJhbGciOiJFUzI1NiJ9.payload.sig");
        assert!(err.is_err());
    }

    #[test]
    fn test_extract_empty_credential() {
        let err = extract_credential("AgentPin ");
        assert!(err.is_err());
    }

    #[test]
    fn test_format_roundtrip() {
        let jwt = "eyJhbGciOiJFUzI1NiJ9.payload.sig";
        let header = format_authorization_header(jwt);
        let extracted = extract_credential(&header).unwrap();
        assert_eq!(extracted, jwt);
    }
}
