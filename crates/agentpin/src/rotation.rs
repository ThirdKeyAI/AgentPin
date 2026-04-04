use chrono::Utc;

use crate::crypto::{generate_key_id, generate_key_pair, load_verifying_key, KeyPair};
use crate::error::Error;
use crate::jwk::{verifying_key_to_jwk, Jwk};
use crate::revocation::add_revoked_key;
use crate::types::discovery::DiscoveryDocument;
use crate::types::revocation::{RevocationDocument, RevocationReason};

/// A plan for key rotation, returned by `prepare_rotation()`.
pub struct RotationPlan {
    pub new_key_pair: KeyPair,
    pub new_kid: String,
    pub new_jwk: Jwk,
    pub old_kid: String,
}

/// Prepare a key rotation: generate a new key pair, compute its kid and JWK.
///
/// The caller should then call `apply_rotation` to add the new key to a
/// discovery document and, after an overlap window, `complete_rotation` to
/// retire the old key.
pub fn prepare_rotation(old_kid: &str) -> Result<RotationPlan, Error> {
    let new_key_pair = generate_key_pair()?;
    let new_kid = generate_key_id(&new_key_pair.public_key_pem)?;
    let vk = load_verifying_key(&new_key_pair.public_key_pem)?;
    let new_jwk = verifying_key_to_jwk(&vk, &new_kid);

    Ok(RotationPlan {
        new_key_pair,
        new_kid,
        new_jwk,
        old_kid: old_kid.to_string(),
    })
}

/// Apply a rotation plan to a discovery document: add the new key while
/// keeping the old key active.  Updates the `updated_at` timestamp.
pub fn apply_rotation(doc: &mut DiscoveryDocument, plan: &RotationPlan) -> Result<(), Error> {
    doc.public_keys.push(plan.new_jwk.clone());
    doc.updated_at = Utc::now().to_rfc3339();
    Ok(())
}

/// Complete a rotation: remove the old key from the discovery document and
/// record it in the revocation document.
///
/// Call this after the overlap window has passed so that relying parties have
/// had time to pick up the new key.
pub fn complete_rotation(
    doc: &mut DiscoveryDocument,
    revocation_doc: &mut RevocationDocument,
    old_kid: &str,
    reason: RevocationReason,
) -> Result<(), Error> {
    doc.public_keys.retain(|k| k.kid != old_kid);
    doc.updated_at = Utc::now().to_rfc3339();
    add_revoked_key(revocation_doc, old_kid, reason);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::pem_to_jwk;
    use crate::revocation::build_revocation_document;
    use crate::types::discovery::{DiscoveryDocument, EntityType};

    fn make_discovery_doc(keys: Vec<Jwk>) -> DiscoveryDocument {
        DiscoveryDocument {
            agentpin_version: "0.1".to_string(),
            entity: "example.com".to_string(),
            entity_type: EntityType::Maker,
            public_keys: keys,
            agents: vec![],
            revocation_endpoint: None,
            policy_url: None,
            schemapin_endpoint: None,
            max_delegation_depth: 2,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_prepare_rotation() {
        let plan = prepare_rotation("old-kid-placeholder").unwrap();
        // kid is a SHA-256 hex digest: 64 hex chars
        assert_eq!(plan.new_kid.len(), 64);
        assert!(plan.new_kid.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(plan.old_kid, "old-kid-placeholder");
        assert_eq!(plan.new_jwk.kid, plan.new_kid);
        assert_eq!(plan.new_jwk.kty, "EC");
        assert_eq!(plan.new_jwk.crv, "P-256");
    }

    #[test]
    fn test_apply_rotation() {
        let old_kp = generate_key_pair().unwrap();
        let old_kid = generate_key_id(&old_kp.public_key_pem).unwrap();
        let old_jwk = pem_to_jwk(&old_kp.public_key_pem, &old_kid).unwrap();

        let mut doc = make_discovery_doc(vec![old_jwk]);
        assert_eq!(doc.public_keys.len(), 1);

        let plan = prepare_rotation(&old_kid).unwrap();
        apply_rotation(&mut doc, &plan).unwrap();

        assert_eq!(doc.public_keys.len(), 2);
        assert!(doc.public_keys.iter().any(|k| k.kid == plan.new_kid));
        assert!(doc.public_keys.iter().any(|k| k.kid == old_kid));
        assert_ne!(doc.updated_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn test_complete_rotation() {
        let old_kp = generate_key_pair().unwrap();
        let old_kid = generate_key_id(&old_kp.public_key_pem).unwrap();
        let old_jwk = pem_to_jwk(&old_kp.public_key_pem, &old_kid).unwrap();

        let mut doc = make_discovery_doc(vec![old_jwk]);
        let plan = prepare_rotation(&old_kid).unwrap();
        apply_rotation(&mut doc, &plan).unwrap();
        assert_eq!(doc.public_keys.len(), 2);

        let mut revocation_doc = build_revocation_document("example.com");
        complete_rotation(
            &mut doc,
            &mut revocation_doc,
            &old_kid,
            RevocationReason::Superseded,
        )
        .unwrap();

        // Old key removed from discovery
        assert_eq!(doc.public_keys.len(), 1);
        assert_eq!(doc.public_keys[0].kid, plan.new_kid);

        // Old key added to revocation
        assert_eq!(revocation_doc.revoked_keys.len(), 1);
        assert_eq!(revocation_doc.revoked_keys[0].kid, old_kid);
        assert_eq!(
            revocation_doc.revoked_keys[0].reason,
            RevocationReason::Superseded
        );
    }
}
