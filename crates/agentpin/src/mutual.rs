//! Mutual-authentication challenge/response (spec §9).
//!
//! The responder signs a domain-separated structure, never the raw nonce:
//!
//! ```text
//! "agentpin-response-v1" 0x00 len(nonce) nonce len(timestamp) timestamp
//!                             len(kid) kid len(binding) binding
//! ```
//!
//! where `binding` is the SHA-256 (hex) of the challenge's
//! `verifier_credential` when present (empty otherwise). Binding the
//! prover's `kid`, the challenge timestamp and the verifier's credential
//! means a response proves possession to this verifier for this challenge
//! only, and the signature can never be reinterpreted as a credential,
//! attestation or AgentCard signature (AP-1, design issue 8).
//!
//! Nonces are single-use by default: every verification goes through a
//! nonce store (a process-wide [`InMemoryNonceStore`] unless the caller
//! supplies one) and the nonce is recorded only after the signature has been
//! verified, so a garbage response cannot burn a legitimate nonce (AP-19).

use std::sync::OnceLock;
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use chrono::Utc;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::RngCore;

use crate::crypto::{self, CTX_RESPONSE};
use crate::error::Error;
use crate::nonce::{InMemoryNonceStore, NonceStore};
use crate::types::mutual::{Challenge, Response};

/// Challenge expiry window in seconds (spec §9.2).
pub const NONCE_EXPIRY_SECS: i64 = 60;
/// Nonce length in bytes (128 bits, spec §9.2).
pub const NONCE_BYTES: usize = 16;
/// Length of a base64url (unpadded) encoding of [`NONCE_BYTES`] bytes.
pub const NONCE_ENCODED_LEN: usize = 22;
/// Wire `type` of a challenge.
pub const CHALLENGE_TYPE: &str = "agentpin-challenge";
/// Wire `type` of a response.
pub const RESPONSE_TYPE: &str = "agentpin-response";

fn default_nonce_store() -> &'static InMemoryNonceStore {
    static STORE: OnceLock<InMemoryNonceStore> = OnceLock::new();
    STORE.get_or_init(InMemoryNonceStore::new)
}

/// Create a challenge with a 128-bit random nonce.
pub fn create_challenge(verifier_credential: Option<&str>) -> Challenge {
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = BASE64URL.encode(nonce_bytes);

    Challenge {
        type_: CHALLENGE_TYPE.to_string(),
        nonce,
        timestamp: Utc::now().to_rfc3339(),
        verifier_credential: verifier_credential.map(|s| s.to_string()),
    }
}

/// Validate that a nonce is exactly 22 canonical base64url characters
/// decoding to 16 bytes. Anything else is rejected so the responder can
/// never be asked to sign caller-shaped bytes.
pub fn validate_nonce(nonce: &str) -> Result<(), Error> {
    if nonce.len() != NONCE_ENCODED_LEN {
        return Err(Error::Jwt(format!(
            "Challenge nonce must be {} base64url characters",
            NONCE_ENCODED_LEN
        )));
    }
    let bytes = BASE64URL
        .decode(nonce)
        .map_err(|_| Error::Jwt("Challenge nonce is not valid base64url".to_string()))?;
    if bytes.len() != NONCE_BYTES || BASE64URL.encode(&bytes) != nonce {
        return Err(Error::Jwt(format!(
            "Challenge nonce must decode to exactly {} bytes",
            NONCE_BYTES
        )));
    }
    Ok(())
}

/// Binding value derived from the challenge's `verifier_credential`:
/// SHA-256 hex of the credential string, or the empty string when absent.
pub fn verifier_binding(challenge: &Challenge) -> String {
    match &challenge.verifier_credential {
        Some(cred) => crypto::sha256_hex(cred.as_bytes()),
        None => String::new(),
    }
}

/// The signing input a responder with key `kid` commits to for `challenge`.
pub fn response_signing_input(challenge: &Challenge, kid: &str) -> Vec<u8> {
    let binding = verifier_binding(challenge);
    crypto::domain_separated_input(
        CTX_RESPONSE,
        &[
            challenge.nonce.as_bytes(),
            challenge.timestamp.as_bytes(),
            kid.as_bytes(),
            binding.as_bytes(),
        ],
    )
}

/// Create a response by signing the domain-separated challenge structure.
///
/// Returns an error when the challenge nonce is not a well-formed 128-bit
/// base64url nonce or the challenge `type` is wrong.
pub fn create_response(
    challenge: &Challenge,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<Response, Error> {
    if challenge.type_ != CHALLENGE_TYPE {
        return Err(Error::Jwt(format!(
            "Challenge type '{}' rejected, must be '{}'",
            challenge.type_, CHALLENGE_TYPE
        )));
    }
    validate_nonce(&challenge.nonce)?;
    let input = response_signing_input(challenge, kid);
    let signature = crypto::sign_bytes(signing_key, &input);
    Ok(Response {
        type_: RESPONSE_TYPE.to_string(),
        nonce: challenge.nonce.clone(),
        signature,
        kid: kid.to_string(),
    })
}

/// Verify a challenge response using the process-wide nonce store, so each
/// nonce is accepted at most once per process.
pub fn verify_response(
    response: &Response,
    challenge: &Challenge,
    verifying_key: &VerifyingKey,
) -> Result<bool, Error> {
    verify_response_with_nonce_store(response, challenge, verifying_key, None)
}

/// Verify a challenge response.
///
/// Order of checks: nonce/type shape, challenge freshness, signature, then
/// single-use recording. Returns `Ok(false)` when the nonce does not match
/// or the signature does not verify; returns `Err` for malformed input,
/// expired challenges and replayed nonces.
///
/// When `nonce_store` is `None` the process-wide [`InMemoryNonceStore`] is
/// used; pass an explicit store to share replay state across processes.
pub fn verify_response_with_nonce_store(
    response: &Response,
    challenge: &Challenge,
    verifying_key: &VerifyingKey,
    nonce_store: Option<&dyn NonceStore>,
) -> Result<bool, Error> {
    if response.type_ != RESPONSE_TYPE || challenge.type_ != CHALLENGE_TYPE {
        return Ok(false);
    }
    if response.nonce != challenge.nonce {
        return Ok(false);
    }
    validate_nonce(&challenge.nonce)?;

    // An unparsable timestamp is treated as expired (fail closed).
    let ts = chrono::DateTime::parse_from_rfc3339(&challenge.timestamp)
        .map_err(|_| Error::Jwt("Challenge timestamp is not valid RFC 3339".to_string()))?;
    let elapsed = Utc::now().timestamp() - ts.timestamp();
    if elapsed > NONCE_EXPIRY_SECS {
        return Err(Error::Jwt(format!(
            "Challenge nonce expired ({} seconds old, max {})",
            elapsed, NONCE_EXPIRY_SECS
        )));
    }

    // Verify the signature before touching the nonce store so a forged
    // response cannot consume a legitimate nonce.
    let input = response_signing_input(challenge, &response.kid);
    if !crypto::verify_bytes(verifying_key, &input, &response.signature)? {
        return Ok(false);
    }

    let store: &dyn NonceStore = match nonce_store {
        Some(s) => s,
        None => default_nonce_store(),
    };
    let fresh = store.check_and_record(
        &response.nonce,
        Duration::from_secs(NONCE_EXPIRY_SECS as u64),
    )?;
    if !fresh {
        return Err(Error::Jwt("Nonce has already been used".to_string()));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn keys() -> (SigningKey, VerifyingKey) {
        let kp = crypto::generate_key_pair().unwrap();
        (
            crypto::load_signing_key(&kp.private_key_pem).unwrap(),
            crypto::load_verifying_key(&kp.public_key_pem).unwrap(),
        )
    }

    #[test]
    fn test_challenge_response_roundtrip() {
        let (sk, vk) = keys();
        let challenge = create_challenge(None);
        assert_eq!(challenge.type_, "agentpin-challenge");
        assert!(!challenge.nonce.is_empty());

        let response = create_response(&challenge, &sk, "test-key").unwrap();
        assert_eq!(response.type_, "agentpin-response");
        assert_eq!(response.nonce, challenge.nonce);

        let valid = verify_response(&response, &challenge, &vk).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (sk1, _) = keys();
        let (_, vk2) = keys();
        let challenge = create_challenge(None);
        let response = create_response(&challenge, &sk1, "key1").unwrap();
        assert!(!verify_response(&response, &challenge, &vk2).unwrap());
    }

    #[test]
    fn test_nonce_mismatch_rejected() {
        let (sk, vk) = keys();
        let challenge = create_challenge(None);
        let mut response = create_response(&challenge, &sk, "test-key").unwrap();
        response.nonce = "wrong-nonce".to_string();
        assert!(!verify_response(&response, &challenge, &vk).unwrap());
    }

    #[test]
    fn test_expired_nonce_rejected() {
        let (sk, vk) = keys();
        let mut challenge = create_challenge(None);
        let past = Utc::now() - chrono::Duration::seconds(120);
        challenge.timestamp = past.to_rfc3339();
        let response = create_response(&challenge, &sk, "test-key").unwrap();
        assert!(verify_response(&response, &challenge, &vk).is_err());
    }

    #[test]
    fn test_nonce_is_128_bits() {
        let challenge = create_challenge(None);
        let nonce_bytes = BASE64URL.decode(&challenge.nonce).unwrap();
        assert_eq!(nonce_bytes.len(), 16);
        assert_eq!(challenge.nonce.len(), NONCE_ENCODED_LEN);
    }

    #[test]
    fn test_challenge_with_verifier_credential() {
        let challenge = create_challenge(Some("eyJ...test-jwt"));
        assert_eq!(
            challenge.verifier_credential,
            Some("eyJ...test-jwt".to_string())
        );
    }

    #[test]
    fn test_verify_with_nonce_store() {
        let (sk, vk) = keys();
        let store = crate::nonce::InMemoryNonceStore::new();
        let challenge = create_challenge(None);
        let response = create_response(&challenge, &sk, "test-key").unwrap();

        let valid =
            verify_response_with_nonce_store(&response, &challenge, &vk, Some(&store)).unwrap();
        assert!(valid);

        let result = verify_response_with_nonce_store(&response, &challenge, &vk, Some(&store));
        assert!(result.is_err(), "Replayed nonce should be rejected");
    }

    /// AP-19: nonces are single-use even when the caller does not pass a
    /// store — the process-wide default store catches the replay.
    #[test]
    fn test_default_store_rejects_replay() {
        let (sk, vk) = keys();
        let challenge = create_challenge(None);
        let response = create_response(&challenge, &sk, "test-key").unwrap();
        assert!(verify_response(&response, &challenge, &vk).unwrap());
        assert!(verify_response(&response, &challenge, &vk).is_err());
    }

    /// AP-19: a forged response must not burn the nonce for the legitimate
    /// responder.
    #[test]
    fn test_forged_response_does_not_consume_nonce() {
        let (sk, vk) = keys();
        let (attacker_sk, _) = keys();
        let challenge = create_challenge(None);
        let forged = create_response(&challenge, &attacker_sk, "test-key").unwrap();
        assert!(!verify_response(&forged, &challenge, &vk).unwrap());
        let genuine = create_response(&challenge, &sk, "test-key").unwrap();
        assert!(verify_response(&genuine, &challenge, &vk).unwrap());
    }

    /// AP-19: an unparsable challenge timestamp is treated as expired.
    #[test]
    fn test_malformed_timestamp_rejected() {
        let (sk, vk) = keys();
        let mut challenge = create_challenge(None);
        challenge.timestamp = "not-a-timestamp".to_string();
        let response = create_response(&challenge, &sk, "test-key").unwrap();
        assert!(verify_response(&response, &challenge, &vk).is_err());
    }

    /// AP-1: the responder refuses to sign a nonce that is not a well-formed
    /// 128-bit base64url value, so it cannot be used as a signing oracle for
    /// a JWT signing input.
    #[test]
    fn test_create_response_rejects_non_nonce_challenge() {
        let (sk, _) = keys();
        let header = crate::jwt::base64url_encode(
            br#"{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"k"}"#,
        );
        let payload = crate::jwt::base64url_encode(br#"{"iss":"example.com"}"#);
        let mut challenge = create_challenge(None);
        challenge.nonce = format!("{}.{}", header, payload);
        assert!(create_response(&challenge, &sk, "k").is_err());

        // Wrong length / non-canonical encodings are rejected too.
        challenge.nonce = "AAAAAAAAAAAAAAAAAAAAAA==".to_string();
        assert!(create_response(&challenge, &sk, "k").is_err());
        challenge.nonce = "AAAAAAAAAAAAAAAAAAAAAB".to_string(); // non-canonical trailing bits
        assert!(create_response(&challenge, &sk, "k").is_err());
        challenge.nonce = "AAAAAAAAAAAAAAAAAAAAAA".to_string(); // canonical
        assert!(create_response(&challenge, &sk, "k").is_ok());
    }

    /// AP-1: even if a responder were coerced into signing, the response
    /// signature is over a domain-separated structure and is not a valid
    /// signature over the nonce bytes themselves.
    #[test]
    fn test_response_signature_is_domain_separated() {
        let (sk, vk) = keys();
        let challenge = create_challenge(Some("eyJ.verifier.jwt"));
        let response = create_response(&challenge, &sk, "test-key").unwrap();
        assert!(
            !crypto::verify_bytes(&vk, challenge.nonce.as_bytes(), &response.signature).unwrap()
        );
        // Changing the prover kid or the verifier binding breaks the signature.
        let mut other_kid = response.clone();
        other_kid.kid = "other-key".to_string();
        assert!(!verify_response(&other_kid, &challenge, &vk).unwrap());
        let mut other_verifier = challenge.clone();
        other_verifier.verifier_credential = Some("eyJ.someone.else".to_string());
        assert!(!verify_response(&response, &other_verifier, &vk).unwrap());
    }

    #[test]
    fn test_wrong_type_rejected() {
        let (sk, vk) = keys();
        let challenge = create_challenge(None);
        let mut response = create_response(&challenge, &sk, "test-key").unwrap();
        response.type_ = "agentpin-challenge".to_string();
        assert!(!verify_response(&response, &challenge, &vk).unwrap());
    }
}
