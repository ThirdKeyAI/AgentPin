use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use chrono::Utc;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::RngCore;

use crate::crypto;
use crate::error::Error;
use crate::nonce::NonceStore;
use crate::types::mutual::{Challenge, Response};

const NONCE_EXPIRY_SECS: i64 = 60;

/// Create a challenge with a 128-bit random nonce.
pub fn create_challenge(verifier_credential: Option<&str>) -> Challenge {
    let mut nonce_bytes = [0u8; 16]; // 128 bits
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = BASE64URL.encode(nonce_bytes);

    Challenge {
        type_: "agentpin-challenge".to_string(),
        nonce,
        timestamp: Utc::now().to_rfc3339(),
        verifier_credential: verifier_credential.map(|s| s.to_string()),
    }
}

/// Create a response by signing the challenge nonce.
pub fn create_response(challenge: &Challenge, signing_key: &SigningKey, kid: &str) -> Response {
    let signature = crypto::sign_bytes(signing_key, challenge.nonce.as_bytes());
    Response {
        type_: "agentpin-response".to_string(),
        nonce: challenge.nonce.clone(),
        signature,
        kid: kid.to_string(),
    }
}

/// Verify a challenge response: check signature and that nonce hasn't expired.
pub fn verify_response(
    response: &Response,
    challenge: &Challenge,
    verifying_key: &VerifyingKey,
) -> Result<bool, Error> {
    verify_response_with_nonce_store(response, challenge, verifying_key, None)
}

/// Verify a challenge response with optional nonce deduplication.
///
/// When a `nonce_store` is provided, the response nonce is checked against
/// previously seen nonces to prevent replay attacks within the validity window.
pub fn verify_response_with_nonce_store(
    response: &Response,
    challenge: &Challenge,
    verifying_key: &VerifyingKey,
    nonce_store: Option<&dyn NonceStore>,
) -> Result<bool, Error> {
    // Check nonce matches
    if response.nonce != challenge.nonce {
        return Ok(false);
    }

    // Check timestamp hasn't expired
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&challenge.timestamp) {
        let elapsed = Utc::now().timestamp() - ts.timestamp();
        if elapsed > NONCE_EXPIRY_SECS {
            return Err(Error::Jwt(format!(
                "Challenge nonce expired ({} seconds old, max {})",
                elapsed, NONCE_EXPIRY_SECS
            )));
        }
    }

    // Check nonce deduplication if a store is provided
    if let Some(store) = nonce_store {
        let fresh = store.check_and_record(&response.nonce, Duration::from_secs(60))?;
        if !fresh {
            return Err(Error::Jwt("Nonce has already been used".to_string()));
        }
    }

    // Verify signature over the nonce
    crypto::verify_bytes(
        verifying_key,
        challenge.nonce.as_bytes(),
        &response.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn test_challenge_response_roundtrip() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let challenge = create_challenge(None);
        assert_eq!(challenge.type_, "agentpin-challenge");
        assert!(!challenge.nonce.is_empty());

        let response = create_response(&challenge, &sk, "test-key");
        assert_eq!(response.type_, "agentpin-response");
        assert_eq!(response.nonce, challenge.nonce);

        let valid = verify_response(&response, &challenge, &vk).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_wrong_key_rejected() {
        let kp1 = crypto::generate_key_pair().unwrap();
        let kp2 = crypto::generate_key_pair().unwrap();
        let sk1 = crypto::load_signing_key(&kp1.private_key_pem).unwrap();
        let vk2 = crypto::load_verifying_key(&kp2.public_key_pem).unwrap();

        let challenge = create_challenge(None);
        let response = create_response(&challenge, &sk1, "key1");

        let valid = verify_response(&response, &challenge, &vk2).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_nonce_mismatch_rejected() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let challenge = create_challenge(None);
        let mut response = create_response(&challenge, &sk, "test-key");
        response.nonce = "wrong-nonce".to_string();

        let valid = verify_response(&response, &challenge, &vk).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_expired_nonce_rejected() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let mut challenge = create_challenge(None);
        // Set timestamp to 120 seconds ago
        let past = Utc::now() - chrono::Duration::seconds(120);
        challenge.timestamp = past.to_rfc3339();

        let response = create_response(&challenge, &sk, "test-key");
        let result = verify_response(&response, &challenge, &vk);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_is_128_bits() {
        let challenge = create_challenge(None);
        let nonce_bytes = BASE64URL.decode(&challenge.nonce).unwrap();
        assert_eq!(nonce_bytes.len(), 16); // 128 bits = 16 bytes
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
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let store = crate::nonce::InMemoryNonceStore::new();
        let challenge = create_challenge(None);
        let response = create_response(&challenge, &sk, "test-key");

        // First verification should succeed.
        let valid =
            verify_response_with_nonce_store(&response, &challenge, &vk, Some(&store)).unwrap();
        assert!(valid);

        // Second verification with the same nonce should fail (replay).
        let result = verify_response_with_nonce_store(&response, &challenge, &vk, Some(&store));
        assert!(result.is_err(), "Replayed nonce should be rejected");
    }

    #[test]
    fn test_verify_without_nonce_store() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let challenge = create_challenge(None);
        let response = create_response(&challenge, &sk, "test-key");

        // Without a nonce store, same nonce can be verified multiple times.
        let valid1 = verify_response(&response, &challenge, &vk).unwrap();
        assert!(valid1);

        let valid2 = verify_response(&response, &challenge, &vk).unwrap();
        assert!(valid2);
    }
}
