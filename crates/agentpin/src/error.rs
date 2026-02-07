use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("ECDSA error: {0}")]
    Ecdsa(String),

    #[error("PKCS8 error: {0}")]
    Pkcs8(String),

    #[error("SPKI error: {0}")]
    Spki(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid key format")]
    InvalidKeyFormat,

    #[error("Signature verification failed")]
    SignatureInvalid,

    #[error("JWT error: {0}")]
    Jwt(String),

    #[error("Verification failed: {code}: {message}")]
    Verification { code: ErrorCode, message: String },

    #[error("Discovery error: {0}")]
    Discovery(String),

    #[error("Revocation error: {0}")]
    Revocation(String),

    #[error("Delegation error: {0}")]
    Delegation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[cfg(feature = "fetch")]
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

impl From<p256::pkcs8::Error> for Error {
    fn from(err: p256::pkcs8::Error) -> Self {
        Error::Pkcs8(err.to_string())
    }
}

impl From<p256::pkcs8::spki::Error> for Error {
    fn from(err: p256::pkcs8::spki::Error) -> Self {
        Error::Spki(err.to_string())
    }
}

impl From<p256::ecdsa::Error> for Error {
    fn from(err: p256::ecdsa::Error) -> Self {
        Error::Ecdsa(err.to_string())
    }
}

/// Error codes from spec section 6.7
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErrorCode {
    #[serde(rename = "SIGNATURE_INVALID")]
    SignatureInvalid,
    #[serde(rename = "KEY_NOT_FOUND")]
    KeyNotFound,
    #[serde(rename = "KEY_EXPIRED")]
    KeyExpired,
    #[serde(rename = "KEY_REVOKED")]
    KeyRevoked,
    #[serde(rename = "CREDENTIAL_EXPIRED")]
    CredentialExpired,
    #[serde(rename = "CREDENTIAL_REVOKED")]
    CredentialRevoked,
    #[serde(rename = "AGENT_NOT_FOUND")]
    AgentNotFound,
    #[serde(rename = "AGENT_INACTIVE")]
    AgentInactive,
    #[serde(rename = "CAPABILITY_EXCEEDED")]
    CapabilityExceeded,
    #[serde(rename = "CONSTRAINT_VIOLATION")]
    ConstraintViolation,
    #[serde(rename = "DELEGATION_INVALID")]
    DelegationInvalid,
    #[serde(rename = "DELEGATION_DEPTH_EXCEEDED")]
    DelegationDepthExceeded,
    #[serde(rename = "DISCOVERY_FETCH_FAILED")]
    DiscoveryFetchFailed,
    #[serde(rename = "DISCOVERY_INVALID")]
    DiscoveryInvalid,
    #[serde(rename = "DOMAIN_MISMATCH")]
    DomainMismatch,
    #[serde(rename = "AUDIENCE_MISMATCH")]
    AudienceMismatch,
    #[serde(rename = "ALGORITHM_REJECTED")]
    AlgorithmRejected,
    #[serde(rename = "KEY_PIN_MISMATCH")]
    KeyPinMismatch,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorCode::SignatureInvalid => "SIGNATURE_INVALID",
            ErrorCode::KeyNotFound => "KEY_NOT_FOUND",
            ErrorCode::KeyExpired => "KEY_EXPIRED",
            ErrorCode::KeyRevoked => "KEY_REVOKED",
            ErrorCode::CredentialExpired => "CREDENTIAL_EXPIRED",
            ErrorCode::CredentialRevoked => "CREDENTIAL_REVOKED",
            ErrorCode::AgentNotFound => "AGENT_NOT_FOUND",
            ErrorCode::AgentInactive => "AGENT_INACTIVE",
            ErrorCode::CapabilityExceeded => "CAPABILITY_EXCEEDED",
            ErrorCode::ConstraintViolation => "CONSTRAINT_VIOLATION",
            ErrorCode::DelegationInvalid => "DELEGATION_INVALID",
            ErrorCode::DelegationDepthExceeded => "DELEGATION_DEPTH_EXCEEDED",
            ErrorCode::DiscoveryFetchFailed => "DISCOVERY_FETCH_FAILED",
            ErrorCode::DiscoveryInvalid => "DISCOVERY_INVALID",
            ErrorCode::DomainMismatch => "DOMAIN_MISMATCH",
            ErrorCode::AudienceMismatch => "AUDIENCE_MISMATCH",
            ErrorCode::AlgorithmRejected => "ALGORITHM_REJECTED",
            ErrorCode::KeyPinMismatch => "KEY_PIN_MISMATCH",
        };
        write!(f, "{}", s)
    }
}
