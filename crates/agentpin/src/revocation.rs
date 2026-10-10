use chrono::Utc;

use crate::error::Error;
use crate::types::revocation::{
    RevocationDocument, RevocationReason, RevokedAgent, RevokedCredential, RevokedKey,
};

/// Build an empty revocation document.
pub fn build_revocation_document(entity: &str) -> RevocationDocument {
    RevocationDocument {
        agentpin_version: "0.1".to_string(),
        entity: entity.to_string(),
        updated_at: Utc::now().to_rfc3339(),
        revoked_credentials: vec![],
        revoked_agents: vec![],
        revoked_keys: vec![],
        kid: None,
        signature: None,
    }
}

/// Add a revoked credential to the document.
pub fn add_revoked_credential(doc: &mut RevocationDocument, jti: &str, reason: RevocationReason) {
    doc.revoked_credentials.push(RevokedCredential {
        jti: jti.to_string(),
        revoked_at: Utc::now().to_rfc3339(),
        reason,
    });
    doc.updated_at = Utc::now().to_rfc3339();
}

/// Add a revoked agent to the document.
pub fn add_revoked_agent(doc: &mut RevocationDocument, agent_id: &str, reason: RevocationReason) {
    doc.revoked_agents.push(RevokedAgent {
        agent_id: agent_id.to_string(),
        revoked_at: Utc::now().to_rfc3339(),
        reason,
    });
    doc.updated_at = Utc::now().to_rfc3339();
}

/// Add a revoked key to the document.
pub fn add_revoked_key(doc: &mut RevocationDocument, kid: &str, reason: RevocationReason) {
    doc.revoked_keys.push(RevokedKey {
        kid: kid.to_string(),
        revoked_at: Utc::now().to_rfc3339(),
        reason,
    });
    doc.updated_at = Utc::now().to_rfc3339();
}

/// Check if a credential is revoked. Returns error with the matching reason if revoked.
pub fn check_revocation(
    doc: &RevocationDocument,
    jti: &str,
    agent_id: &str,
    kid: &str,
) -> Result<(), Error> {
    if let Some(rc) = doc.revoked_credentials.iter().find(|r| r.jti == jti) {
        return Err(Error::Verification {
            code: crate::error::ErrorCode::CredentialRevoked,
            message: format!("Credential {} revoked: {:?}", jti, rc.reason),
        });
    }
    if let Some(ra) = doc.revoked_agents.iter().find(|r| r.agent_id == agent_id) {
        return Err(Error::Verification {
            code: crate::error::ErrorCode::AgentInactive,
            message: format!("Agent {} revoked: {:?}", agent_id, ra.reason),
        });
    }
    if let Some(rk) = doc.revoked_keys.iter().find(|r| r.kid == kid) {
        return Err(Error::Verification {
            code: crate::error::ErrorCode::KeyRevoked,
            message: format!("Key {} revoked: {:?}", kid, rk.reason),
        });
    }
    Ok(())
}

/// Fetch a revocation document from a URL. Any failure, including HTTP
/// 404, is an error so callers fail closed for an explicitly declared
/// endpoint.
#[cfg(feature = "fetch")]
pub async fn fetch_revocation_document(url: &str) -> Result<RevocationDocument, Error> {
    fetch_revocation_document_if_present(url)
        .await?
        .ok_or_else(|| Error::Revocation(format!("HTTP 404 fetching {}", url)))
}

/// Fetch a revocation document from a URL, returning `Ok(None)` on HTTP
/// 404. Used for the spec §8.1 default endpoint when the discovery document
/// declares none: an issuer that publishes no revocation document is not an
/// error, but any other failure still fails closed.
#[cfg(feature = "fetch")]
pub async fn fetch_revocation_document_if_present(
    url: &str,
) -> Result<Option<RevocationDocument>, Error> {
    // Only https URLs with a domain host are ever fetched (AP-12). Same-host
    // binding to the issuer is enforced by the caller / discovery validation.
    crate::domain::https_url_host(url).map_err(|e| Error::Revocation(e.to_string()))?;
    let body = crate::net::fetch_json_bounded(url, &crate::net::FetchOptions::default())
        .await
        .map_err(|e| Error::Revocation(e.to_string()))?;
    match body {
        None => Ok(None),
        Some(bytes) => {
            let doc: RevocationDocument = serde_json::from_slice(&bytes)
                .map_err(|_| Error::Revocation(format!("Invalid JSON from {}", url)))?;
            Ok(Some(doc))
        }
    }
}

// ---------------------------------------------------------------------------
// Signed revocation documents and freshness (design issue 3)
// ---------------------------------------------------------------------------

/// Signing input for a revocation document: the `agentpin-revocation-v1`
/// context over the canonical JSON of the document with `signature` cleared.
pub fn revocation_signing_input(doc: &RevocationDocument) -> Result<Vec<u8>, Error> {
    let mut value = serde_json::to_value(doc)?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signature");
    }
    let canonical = crate::a2a::canonicalize_json(&value)?;
    Ok(crate::crypto::domain_separated_input(
        crate::crypto::CTX_REVOCATION,
        &[&canonical],
    ))
}

/// Sign a revocation document with a discovery-document key.
pub fn sign_revocation_document(
    doc: &mut RevocationDocument,
    signing_key: &p256::ecdsa::SigningKey,
    kid: &str,
) -> Result<(), Error> {
    doc.kid = Some(kid.to_string());
    doc.signature = None;
    let input = revocation_signing_input(doc)?;
    doc.signature = Some(crate::crypto::sign_bytes(signing_key, &input));
    Ok(())
}

/// Validate a revocation document against the discovery document it
/// belongs to: wire version, entity binding, and (when present) its
/// signature under a key from `discovery.public_keys`.
pub fn verify_revocation_document(
    doc: &RevocationDocument,
    discovery: &crate::types::discovery::DiscoveryDocument,
) -> Result<(), Error> {
    if doc.agentpin_version != "0.1" {
        return Err(Error::Revocation(format!(
            "Unsupported revocation document version: {}",
            doc.agentpin_version
        )));
    }
    let doc_entity = crate::domain::normalize_domain(&doc.entity)
        .map_err(|e| Error::Revocation(format!("Invalid revocation entity: {}", e)))?;
    let disc_entity = crate::domain::normalize_domain(&discovery.entity)
        .map_err(|e| Error::Revocation(format!("Invalid discovery entity: {}", e)))?;
    if doc_entity != disc_entity {
        return Err(Error::Revocation(format!(
            "Revocation document entity '{}' does not match discovery entity '{}'",
            doc.entity, discovery.entity
        )));
    }
    if let Some(ref sig) = doc.signature {
        let kid = doc.kid.as_deref().ok_or_else(|| {
            Error::Revocation("Signed revocation document has no kid".to_string())
        })?;
        let jwk = crate::discovery::find_key_by_kid(discovery, kid).ok_or_else(|| {
            Error::Revocation(format!(
                "Revocation document kid '{}' not found in discovery document",
                kid
            ))
        })?;
        let vk = crate::jwk::jwk_to_verifying_key(jwk)?;
        let input = revocation_signing_input(doc)?;
        if !crate::crypto::verify_bytes(&vk, &input, sig)? {
            return Err(Error::Revocation(
                "Revocation document signature did not verify".to_string(),
            ));
        }
    }
    Ok(())
}

/// Reject a revocation document whose `updated_at` is unparsable or older
/// than `max_age_secs`.
pub fn check_revocation_freshness(
    doc: &RevocationDocument,
    max_age_secs: i64,
) -> Result<(), Error> {
    let updated = chrono::DateTime::parse_from_rfc3339(&doc.updated_at).map_err(|_| {
        Error::Revocation("Revocation document updated_at is not RFC 3339".to_string())
    })?;
    let age = Utc::now().timestamp() - updated.timestamp();
    if age > max_age_secs {
        return Err(Error::Revocation(format!(
            "Revocation document is stale ({} seconds old, max {})",
            age, max_age_secs
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_and_add_revocations() {
        let mut doc = build_revocation_document("example.com");
        assert_eq!(doc.entity, "example.com");
        assert!(doc.revoked_credentials.is_empty());

        add_revoked_credential(&mut doc, "jti-123", RevocationReason::KeyCompromise);
        add_revoked_agent(
            &mut doc,
            "urn:agentpin:example.com:bad-agent",
            RevocationReason::PolicyViolation,
        );
        add_revoked_key(&mut doc, "old-key-01", RevocationReason::Superseded);

        assert_eq!(doc.revoked_credentials.len(), 1);
        assert_eq!(doc.revoked_agents.len(), 1);
        assert_eq!(doc.revoked_keys.len(), 1);
    }

    fn discovery_with(
        jwk: crate::jwk::Jwk,
        entity: &str,
    ) -> crate::types::discovery::DiscoveryDocument {
        crate::discovery::build_discovery_document(
            entity,
            crate::types::discovery::EntityType::Maker,
            vec![jwk],
            vec![],
            2,
            "2026-01-15T00:00:00Z",
        )
    }

    /// Design issue 3: a signed revocation document verifies under its
    /// discovery key and any tampering breaks the signature.
    #[test]
    fn test_signed_revocation_document() {
        let kp = crate::crypto::generate_key_pair().unwrap();
        let sk = crate::crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let jwk = crate::jwk::pem_to_jwk(&kp.public_key_pem, "k1").unwrap();
        let discovery = discovery_with(jwk, "example.com");

        let mut doc = build_revocation_document("example.com");
        add_revoked_key(&mut doc, "old", RevocationReason::Superseded);
        verify_revocation_document(&doc, &discovery).unwrap(); // unsigned is allowed
        sign_revocation_document(&mut doc, &sk, "k1").unwrap();
        verify_revocation_document(&doc, &discovery).unwrap();

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: RevocationDocument = serde_json::from_str(&json).unwrap();
        verify_revocation_document(&parsed, &discovery).unwrap();

        let mut tampered = doc.clone();
        tampered.revoked_keys.clear();
        assert!(verify_revocation_document(&tampered, &discovery).is_err());
        let mut wrong_kid = doc.clone();
        wrong_kid.kid = Some("other".to_string());
        assert!(verify_revocation_document(&wrong_kid, &discovery).is_err());
    }

    /// Design issue 3: a revocation document for another entity is rejected.
    #[test]
    fn test_revocation_entity_must_match_discovery() {
        let kp = crate::crypto::generate_key_pair().unwrap();
        let jwk = crate::jwk::pem_to_jwk(&kp.public_key_pem, "k1").unwrap();
        let discovery = discovery_with(jwk, "example.com");
        let doc = build_revocation_document("other.com");
        assert!(verify_revocation_document(&doc, &discovery).is_err());
        let doc = build_revocation_document("EXAMPLE.com.");
        assert!(verify_revocation_document(&doc, &discovery).is_ok());
    }

    /// Design issue 3: stale or unparsable updated_at is rejected when a max
    /// age is enforced.
    #[test]
    fn test_revocation_freshness() {
        let mut doc = build_revocation_document("example.com");
        assert!(check_revocation_freshness(&doc, 3600).is_ok());
        doc.updated_at = (Utc::now() - chrono::Duration::seconds(7200)).to_rfc3339();
        assert!(check_revocation_freshness(&doc, 3600).is_err());
        doc.updated_at = "yesterday".to_string();
        assert!(check_revocation_freshness(&doc, 3600).is_err());
    }

    /// AP-8: a revocation document using the wrong field names (the schema
    /// the old docs published) does not parse, so verifiers fail closed.
    #[test]
    fn test_wrong_field_names_do_not_parse() {
        let wrong = r#"{
          "agentpin_version": "0.1",
          "entity": "example.com",
          "revoked_credentials": [{"id": "jti-123", "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z"}],
          "revoked_agents": [],
          "revoked_keys": [{"id": "example-2025-01", "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z"}],
          "updated_at": "2026-02-15T00:00:00Z"
        }"#;
        assert!(serde_json::from_str::<RevocationDocument>(wrong).is_err());
        let right = wrong
            .replace("\"id\": \"jti-123\"", "\"jti\": \"jti-123\"")
            .replace(
                "\"id\": \"example-2025-01\"",
                "\"kid\": \"example-2025-01\"",
            );
        assert!(serde_json::from_str::<RevocationDocument>(&right).is_ok());
    }

    #[test]
    fn test_check_revocation_clean() {
        let doc = build_revocation_document("example.com");
        assert!(check_revocation(&doc, "jti-1", "agent-1", "key-1").is_ok());
    }

    #[test]
    fn test_check_revocation_credential_revoked() {
        let mut doc = build_revocation_document("example.com");
        add_revoked_credential(&mut doc, "jti-bad", RevocationReason::KeyCompromise);
        assert!(check_revocation(&doc, "jti-bad", "agent-1", "key-1").is_err());
        assert!(check_revocation(&doc, "jti-good", "agent-1", "key-1").is_ok());
    }

    #[test]
    fn test_check_revocation_agent_revoked() {
        let mut doc = build_revocation_document("example.com");
        add_revoked_agent(&mut doc, "bad-agent", RevocationReason::PrivilegeWithdrawn);
        assert!(check_revocation(&doc, "jti-1", "bad-agent", "key-1").is_err());
    }

    #[test]
    fn test_check_revocation_key_revoked() {
        let mut doc = build_revocation_document("example.com");
        add_revoked_key(&mut doc, "bad-key", RevocationReason::Superseded);
        assert!(check_revocation(&doc, "jti-1", "agent-1", "bad-key").is_err());
    }
}
