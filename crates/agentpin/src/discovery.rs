use crate::error::Error;
use crate::jwk::Jwk;
use crate::types::discovery::{AgentDeclaration, DiscoveryDocument, EntityType};

/// Build a new discovery document.
pub fn build_discovery_document(
    entity: &str,
    entity_type: EntityType,
    public_keys: Vec<Jwk>,
    agents: Vec<AgentDeclaration>,
    max_delegation_depth: u8,
    updated_at: &str,
) -> DiscoveryDocument {
    DiscoveryDocument {
        agentpin_version: "0.1".to_string(),
        entity: entity.to_string(),
        entity_type,
        public_keys,
        agents,
        revocation_endpoint: Some(format!(
            "https://{}/.well-known/agent-identity-revocations.json",
            entity
        )),
        policy_url: None,
        schemapin_endpoint: None,
        max_delegation_depth,
        updated_at: updated_at.to_string(),
    }
}

/// Validate a discovery document's basic structural requirements.
pub fn validate_discovery_document(
    doc: &DiscoveryDocument,
    expected_entity: &str,
) -> Result<(), Error> {
    if doc.agentpin_version != "0.1" {
        return Err(Error::Discovery(format!(
            "Unsupported version: {}",
            doc.agentpin_version
        )));
    }
    if doc.entity != expected_entity {
        return Err(Error::Verification {
            code: crate::error::ErrorCode::DomainMismatch,
            message: format!(
                "Discovery entity '{}' does not match expected '{}'",
                doc.entity, expected_entity
            ),
        });
    }
    if doc.public_keys.is_empty() {
        return Err(Error::Discovery(
            "Discovery document must have at least one public key".to_string(),
        ));
    }
    if doc.max_delegation_depth > 3 {
        return Err(Error::Discovery(
            "max_delegation_depth must be 0-3".to_string(),
        ));
    }
    Ok(())
}

/// Find a public key by kid in a discovery document.
pub fn find_key_by_kid<'a>(doc: &'a DiscoveryDocument, kid: &str) -> Option<&'a Jwk> {
    doc.public_keys.iter().find(|k| k.kid == kid)
}

/// Find an agent declaration by agent_id.
pub fn find_agent_by_id<'a>(
    doc: &'a DiscoveryDocument,
    agent_id: &str,
) -> Option<&'a AgentDeclaration> {
    doc.agents.iter().find(|a| a.agent_id == agent_id)
}

/// Fetch a discovery document from a domain over HTTPS.
#[cfg(feature = "fetch")]
pub async fn fetch_discovery_document(domain: &str) -> Result<DiscoveryDocument, Error> {
    let url = format!("https://{}/.well-known/agent-identity.json", domain);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| Error::Discovery(e.to_string()))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| Error::Discovery(format!("Failed to fetch {}: {}", url, e)))?;

    if resp.status().is_redirection() {
        return Err(Error::Discovery(format!(
            "Redirect detected fetching {} (status {}). Redirects are not allowed.",
            url,
            resp.status()
        )));
    }

    if !resp.status().is_success() {
        return Err(Error::Discovery(format!(
            "HTTP {} fetching {}",
            resp.status(),
            url
        )));
    }

    let doc: DiscoveryDocument = resp
        .json()
        .await
        .map_err(|e| Error::Discovery(format!("Invalid JSON from {}: {}", url, e)))?;

    validate_discovery_document(&doc, domain)?;
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::capability::Capability;
    use crate::types::discovery::AgentStatus;

    fn make_test_doc() -> DiscoveryDocument {
        build_discovery_document(
            "example.com",
            EntityType::Maker,
            vec![Jwk {
                kid: "example-2026-01".to_string(),
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: "test-x".to_string(),
                y: "test-y".to_string(),
                use_: "sig".to_string(),
                key_ops: Some(vec!["verify".to_string()]),
                exp: None,
            }],
            vec![AgentDeclaration {
                agent_id: "urn:agentpin:example.com:agent".to_string(),
                agent_type: None,
                name: "Test Agent".to_string(),
                description: None,
                version: None,
                capabilities: vec![Capability::from("read:*")],
                constraints: None,
                maker_attestation: None,
                credential_ttl_max: Some(3600),
                status: AgentStatus::Active,
                directory_listing: None,
            }],
            2,
            "2026-01-15T00:00:00Z",
        )
    }

    #[test]
    fn test_validate_discovery_document() {
        let doc = make_test_doc();
        assert!(validate_discovery_document(&doc, "example.com").is_ok());
    }

    #[test]
    fn test_validate_domain_mismatch() {
        let doc = make_test_doc();
        assert!(validate_discovery_document(&doc, "other.com").is_err());
    }

    #[test]
    fn test_find_key_by_kid() {
        let doc = make_test_doc();
        assert!(find_key_by_kid(&doc, "example-2026-01").is_some());
        assert!(find_key_by_kid(&doc, "nonexistent").is_none());
    }

    #[test]
    fn test_find_agent_by_id() {
        let doc = make_test_doc();
        assert!(find_agent_by_id(&doc, "urn:agentpin:example.com:agent").is_some());
        assert!(find_agent_by_id(&doc, "urn:agentpin:example.com:other").is_none());
    }
}
