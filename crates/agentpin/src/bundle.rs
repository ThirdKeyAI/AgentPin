//! Signed trust bundles (design issue 5).
//!
//! A trust bundle is a root of trust for air-gapped verifiers, so it can be
//! signed by the operator that produced it and given an expiry. The
//! signature covers the `agentpin-bundle-v1` context over the canonical
//! JSON of the bundle with `signature` cleared.

use chrono::Utc;
use p256::ecdsa::{SigningKey, VerifyingKey};

use crate::crypto::{self, CTX_BUNDLE};
use crate::error::Error;
use crate::types::bundle::TrustBundle;

/// Signing input for a trust bundle.
pub fn bundle_signing_input(bundle: &TrustBundle) -> Result<Vec<u8>, Error> {
    let mut value = serde_json::to_value(bundle)?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signature");
    }
    let canonical = crate::a2a::canonicalize_json(&value)?;
    Ok(crypto::domain_separated_input(CTX_BUNDLE, &[&canonical]))
}

/// Sign a trust bundle with the operator key identified by `kid`.
pub fn sign_trust_bundle(
    bundle: &mut TrustBundle,
    signing_key: &SigningKey,
    kid: &str,
) -> Result<(), Error> {
    bundle.kid = Some(kid.to_string());
    bundle.signature = None;
    let input = bundle_signing_input(bundle)?;
    bundle.signature = Some(crypto::sign_bytes(signing_key, &input));
    Ok(())
}

/// Verify a trust bundle's signature under `verifying_key` and reject it
/// when `expires_at` has passed. Unsigned bundles are rejected.
pub fn verify_trust_bundle(
    bundle: &TrustBundle,
    verifying_key: &VerifyingKey,
) -> Result<(), Error> {
    let sig = bundle
        .signature
        .as_deref()
        .ok_or_else(|| Error::Discovery("Trust bundle is not signed".to_string()))?;
    let input = bundle_signing_input(bundle)?;
    if !crypto::verify_bytes(verifying_key, &input, sig)? {
        return Err(Error::Discovery(
            "Trust bundle signature did not verify".to_string(),
        ));
    }
    check_bundle_expiry(bundle)
}

/// Reject a bundle whose `expires_at` is unparsable or in the past.
pub fn check_bundle_expiry(bundle: &TrustBundle) -> Result<(), Error> {
    if let Some(ref exp) = bundle.expires_at {
        let exp_dt = chrono::DateTime::parse_from_rfc3339(exp)
            .map_err(|_| Error::Discovery("Trust bundle expires_at is not RFC 3339".to_string()))?;
        if exp_dt.timestamp() < Utc::now().timestamp() {
            return Err(Error::Discovery("Trust bundle has expired".to_string()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SigningKey, VerifyingKey) {
        let kp = crypto::generate_key_pair().unwrap();
        (
            crypto::load_signing_key(&kp.private_key_pem).unwrap(),
            crypto::load_verifying_key(&kp.public_key_pem).unwrap(),
        )
    }

    #[test]
    fn signed_bundle_round_trips() {
        let (sk, vk) = keys();
        let (_, other_vk) = keys();
        let mut bundle = TrustBundle::new("2026-02-10T00:00:00Z");
        assert!(
            verify_trust_bundle(&bundle, &vk).is_err(),
            "unsigned bundles are rejected"
        );
        sign_trust_bundle(&mut bundle, &sk, "ops-1").unwrap();
        verify_trust_bundle(&bundle, &vk).unwrap();
        let parsed: TrustBundle =
            serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
        verify_trust_bundle(&parsed, &vk).unwrap();
        assert!(verify_trust_bundle(&bundle, &other_vk).is_err());

        let mut tampered = bundle.clone();
        tampered.created_at = "2030-01-01T00:00:00Z".to_string();
        assert!(verify_trust_bundle(&tampered, &vk).is_err());
    }

    #[test]
    fn expired_bundle_is_rejected() {
        let (sk, vk) = keys();
        let mut bundle = TrustBundle::new("2026-02-10T00:00:00Z");
        bundle.expires_at = Some("2020-01-01T00:00:00Z".to_string());
        sign_trust_bundle(&mut bundle, &sk, "ops-1").unwrap();
        assert!(verify_trust_bundle(&bundle, &vk).is_err());
        bundle.expires_at = Some("2099-01-01T00:00:00Z".to_string());
        sign_trust_bundle(&mut bundle, &sk, "ops-1").unwrap();
        verify_trust_bundle(&bundle, &vk).unwrap();
    }
}
