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

/// Fetch a revocation document from a URL.
#[cfg(feature = "fetch")]
pub async fn fetch_revocation_document(url: &str) -> Result<RevocationDocument, Error> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Revocation(e.to_string()))?;

    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| Error::Revocation(format!("Failed to fetch {}: {}", url, e)))?;

    if !resp.status().is_success() {
        return Err(Error::Revocation(format!(
            "HTTP {} fetching {}",
            resp.status(),
            url
        )));
    }

    let doc: RevocationDocument = resp
        .json()
        .await
        .map_err(|e| Error::Revocation(format!("Invalid JSON from {}: {}", url, e)))?;

    Ok(doc)
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
