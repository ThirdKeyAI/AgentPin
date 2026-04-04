//! End-to-end integration tests for AgentPin.

use agentpin::credential::issue_credential;
use agentpin::crypto::{generate_key_id, generate_key_pair, load_signing_key, load_verifying_key};
use agentpin::discovery::{find_agent_by_id, find_key_by_kid, validate_discovery_document};
use agentpin::jwk::pem_to_jwk;
use agentpin::jwt::{decode_jwt_unverified, verify_jwt};
use agentpin::mutual::{create_challenge, create_response, verify_response_with_nonce_store};
use agentpin::nonce::InMemoryNonceStore;
use agentpin::pinning::{check_pinning, KeyPinStore, PinningResult};
use agentpin::resolver::TrustBundleResolver;
use agentpin::revocation::{add_revoked_key, build_revocation_document, check_revocation};
use agentpin::rotation::{apply_rotation, complete_rotation, prepare_rotation};
use agentpin::transport;
use agentpin::types::bundle::TrustBundle;
use agentpin::types::capability::Capability;
use agentpin::types::discovery::*;
use agentpin::types::revocation::RevocationReason;
use agentpin::verification::{
    verify_credential_offline, verify_credential_with_resolver, VerifierConfig,
};

fn make_test_setup() -> (String, String, String, String, DiscoveryDocument) {
    let kp = generate_key_pair().unwrap();
    let kid = generate_key_id(&kp.public_key_pem).unwrap();
    let jwk = pem_to_jwk(&kp.public_key_pem, &kid).unwrap();
    let doc = DiscoveryDocument {
        agentpin_version: "0.1".to_string(),
        entity: "example.com".to_string(),
        entity_type: EntityType::Maker,
        public_keys: vec![jwk],
        agents: vec![AgentDeclaration {
            agent_id: "urn:agentpin:example.com:test-agent".to_string(),
            agent_type: None,
            name: "Test Agent".to_string(),
            description: None,
            version: None,
            capabilities: vec![Capability::from("read:*"), Capability::from("write:report")],
            constraints: None,
            maker_attestation: None,
            credential_ttl_max: Some(3600),
            status: AgentStatus::Active,
            directory_listing: None,
        }],
        revocation_endpoint: None,
        policy_url: None,
        schemapin_endpoint: None,
        max_delegation_depth: 2,
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };
    (
        kp.private_key_pem,
        kp.public_key_pem,
        kid,
        "urn:agentpin:example.com:test-agent".to_string(),
        doc,
    )
}

#[test]
fn test_maker_deployer_flow() {
    let (private_pem, public_pem, kid, agent_id, doc) = make_test_setup();

    // Validate the discovery document
    validate_discovery_document(&doc, "example.com").unwrap();
    assert!(find_key_by_kid(&doc, &kid).is_some());
    assert!(find_agent_by_id(&doc, &agent_id).is_some());

    // Issue a credential
    let sk = load_signing_key(&private_pem).unwrap();
    let jwt_str = issue_credential(
        &sk,
        &kid,
        "example.com",
        &agent_id,
        Some("verifier.com"),
        vec![
            Capability::from("read:data"),
            Capability::from("write:report"),
        ],
        None,
        None,
        3600,
    )
    .unwrap();

    // Decode unverified to inspect
    let (header, payload, _sig) = decode_jwt_unverified(&jwt_str).unwrap();
    assert_eq!(header.alg, "ES256");
    assert_eq!(header.typ, "agentpin-credential+jwt");
    assert_eq!(header.kid, kid);
    assert_eq!(payload.iss, "example.com");
    assert_eq!(payload.sub, agent_id);

    // Verify signature
    let vk = load_verifying_key(&public_pem).unwrap();
    let (verified_header, verified_payload) = verify_jwt(&jwt_str, &vk).unwrap();
    assert_eq!(verified_header.kid, kid);
    assert_eq!(verified_payload.iss, "example.com");

    // Full offline verification via TrustBundleResolver
    let revocation = build_revocation_document("example.com");
    let bundle = TrustBundle {
        agentpin_bundle_version: "0.1".to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        documents: vec![doc.clone()],
        revocations: vec![revocation],
    };
    let resolver = TrustBundleResolver::new(&bundle);
    let mut pin_store = KeyPinStore::new();
    let config = VerifierConfig::default();

    let result = verify_credential_with_resolver(
        &jwt_str,
        &resolver,
        &mut pin_store,
        Some("verifier.com"),
        &config,
    );
    assert!(result.valid, "Expected valid, got: {:?}", result);
    assert_eq!(result.agent_id, Some(agent_id));
    assert_eq!(result.issuer, Some("example.com".to_string()));
}

#[test]
fn test_revocation_flow() {
    let (private_pem, _public_pem, kid, agent_id, doc) = make_test_setup();

    let sk = load_signing_key(&private_pem).unwrap();
    let jwt_str = issue_credential(
        &sk,
        &kid,
        "example.com",
        &agent_id,
        None,
        vec![Capability::from("read:data")],
        None,
        None,
        3600,
    )
    .unwrap();

    // Parse JWT to get the jti
    let (_header, payload, _sig) = decode_jwt_unverified(&jwt_str).unwrap();

    // Clean revocation: should pass
    let mut rev_doc = build_revocation_document("example.com");
    check_revocation(&rev_doc, &payload.jti, &agent_id, &kid).unwrap();

    // Add revoked key
    add_revoked_key(&mut rev_doc, &kid, RevocationReason::KeyCompromise);

    // Now check_revocation should fail
    let result = check_revocation(&rev_doc, &payload.jti, &agent_id, &kid);
    assert!(result.is_err(), "Expected revocation check to fail");

    // Full offline verification should also fail
    let mut pin_store = KeyPinStore::new();
    let config = VerifierConfig::default();
    let vresult = verify_credential_offline(
        &jwt_str,
        &doc,
        Some(&rev_doc),
        &mut pin_store,
        None,
        &config,
    );
    assert!(!vresult.valid);
}

#[test]
fn test_mutual_verification_with_nonce_store() {
    let kp = generate_key_pair().unwrap();
    let sk = load_signing_key(&kp.private_key_pem).unwrap();
    let vk = load_verifying_key(&kp.public_key_pem).unwrap();

    let store = InMemoryNonceStore::new();
    let challenge = create_challenge(None);
    let response = create_response(&challenge, &sk, "test-key");

    // First verification should succeed
    let valid = verify_response_with_nonce_store(&response, &challenge, &vk, Some(&store)).unwrap();
    assert!(valid);

    // Second verification with the same nonce should fail (replay)
    let result = verify_response_with_nonce_store(&response, &challenge, &vk, Some(&store));
    assert!(result.is_err(), "Replayed nonce should be rejected");
}

#[test]
fn test_transport_roundtrip() {
    let kp = generate_key_pair().unwrap();
    let sk = load_signing_key(&kp.private_key_pem).unwrap();
    let kid = generate_key_id(&kp.public_key_pem).unwrap();

    let jwt_str = issue_credential(
        &sk,
        &kid,
        "example.com",
        "urn:agentpin:example.com:test-agent",
        None,
        vec![Capability::from("read:data")],
        None,
        None,
        3600,
    )
    .unwrap();

    // HTTP roundtrip
    let http_header = transport::http::format_authorization_header(&jwt_str);
    let http_extracted = transport::http::extract_credential(&http_header).unwrap();
    assert_eq!(http_extracted, jwt_str);

    // MCP roundtrip
    let mcp_meta = transport::mcp::format_meta_field(&jwt_str);
    let mcp_extracted = transport::mcp::extract_credential(&mcp_meta).unwrap();
    assert_eq!(mcp_extracted, jwt_str);

    // WebSocket roundtrip
    let ws_msg = transport::websocket::format_auth_message(&jwt_str);
    let ws_extracted = transport::websocket::extract_credential(&ws_msg).unwrap();
    assert_eq!(ws_extracted, jwt_str);

    // gRPC roundtrip
    let grpc_val = transport::grpc::format_metadata_value(&jwt_str);
    let grpc_extracted = transport::grpc::extract_credential(&grpc_val).unwrap();
    assert_eq!(grpc_extracted, jwt_str);
}

#[test]
fn test_key_rotation_lifecycle() {
    let kp = generate_key_pair().unwrap();
    let old_kid = generate_key_id(&kp.public_key_pem).unwrap();
    let old_jwk = pem_to_jwk(&kp.public_key_pem, &old_kid).unwrap();

    let mut doc = DiscoveryDocument {
        agentpin_version: "0.1".to_string(),
        entity: "example.com".to_string(),
        entity_type: EntityType::Maker,
        public_keys: vec![old_jwk],
        agents: vec![],
        revocation_endpoint: None,
        policy_url: None,
        schemapin_endpoint: None,
        max_delegation_depth: 2,
        updated_at: "2026-01-01T00:00:00Z".to_string(),
    };

    assert_eq!(doc.public_keys.len(), 1);

    // Prepare rotation
    let plan = prepare_rotation(&old_kid).unwrap();
    assert_ne!(plan.new_kid, old_kid);

    // Apply rotation: both keys should be present
    apply_rotation(&mut doc, &plan).unwrap();
    assert_eq!(doc.public_keys.len(), 2);
    assert!(doc.public_keys.iter().any(|k| k.kid == old_kid));
    assert!(doc.public_keys.iter().any(|k| k.kid == plan.new_kid));

    // Complete rotation: old key removed, added to revocation
    let mut rev_doc = build_revocation_document("example.com");
    complete_rotation(
        &mut doc,
        &mut rev_doc,
        &old_kid,
        RevocationReason::Superseded,
    )
    .unwrap();

    assert_eq!(doc.public_keys.len(), 1);
    assert_eq!(doc.public_keys[0].kid, plan.new_kid);
    assert_eq!(rev_doc.revoked_keys.len(), 1);
    assert_eq!(rev_doc.revoked_keys[0].kid, old_kid);
    assert_eq!(rev_doc.revoked_keys[0].reason, RevocationReason::Superseded);
}

#[test]
fn test_pinning_flow() {
    let kp1 = generate_key_pair().unwrap();
    let kid1 = generate_key_id(&kp1.public_key_pem).unwrap();
    let jwk1 = pem_to_jwk(&kp1.public_key_pem, &kid1).unwrap();

    let mut store = KeyPinStore::new();

    // First verification pins the key
    let result1 = check_pinning(&mut store, "example.com", &jwk1).unwrap();
    assert_eq!(result1, PinningResult::FirstUse);

    // Same key succeeds
    let result2 = check_pinning(&mut store, "example.com", &jwk1).unwrap();
    assert_eq!(result2, PinningResult::Matched);

    // Different key triggers error
    let kp2 = generate_key_pair().unwrap();
    let kid2 = generate_key_id(&kp2.public_key_pem).unwrap();
    let jwk2 = pem_to_jwk(&kp2.public_key_pem, &kid2).unwrap();

    let result3 = check_pinning(&mut store, "example.com", &jwk2);
    assert!(
        result3.is_err(),
        "Different key should trigger pinning error"
    );
}
