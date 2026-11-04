//! End-to-end Web Bot Auth flow: an agent signs a request with its Ed25519
//! key and carries a cnf-bound AgentPin credential; the origin verifies the
//! signature, the credential and the binding between them.

use agentpin::credential::{issue_bound_credential, issue_credential};
use agentpin::crypto::{generate_key_id, generate_key_pair, load_signing_key};
use agentpin::discovery::validate_discovery_document;
use agentpin::httpsig::{Component, HttpRequest};
use agentpin::jwk::pem_to_jwk;
use agentpin::pinning::KeyPinStore;
use agentpin::resolver::TrustBundleResolver;
use agentpin::revocation::build_revocation_document;
use agentpin::transport::http::format_authorization_header;
use agentpin::types::bundle::TrustBundle;
use agentpin::types::capability::Capability;
use agentpin::types::discovery::*;
use agentpin::verification::VerifierConfig;
use agentpin::wba::{
    self, generate_signing_key, sign_request, verify_bound_request, well_known_directory,
    BindingFailure, Directory, DirectoryKeyStore, SignOptions, VerifyOptions, WbaOutcome,
};

const AGENT_ID: &str = "urn:agentpin:example.com:crawler";

struct Setup {
    es256: p256::ecdsa::SigningKey,
    kid: String,
    discovery: DiscoveryDocument,
}

fn setup(web_bot_auth: Option<WebBotAuth>) -> Setup {
    let kp = generate_key_pair().unwrap();
    let kid = generate_key_id(&kp.public_key_pem).unwrap();
    let discovery = DiscoveryDocument {
        agentpin_version: "0.1".to_string(),
        entity: "example.com".to_string(),
        entity_type: EntityType::Maker,
        public_keys: vec![pem_to_jwk(&kp.public_key_pem, &kid).unwrap()],
        agents: vec![AgentDeclaration {
            agent_id: AGENT_ID.to_string(),
            agent_type: None,
            name: "Crawler".to_string(),
            description: None,
            version: None,
            capabilities: vec![Capability::from("read:*")],
            constraints: None,
            maker_attestation: None,
            credential_ttl_max: None,
            status: AgentStatus::Active,
            directory_listing: None,
        }],
        revocation_endpoint: None,
        policy_url: None,
        schemapin_endpoint: None,
        a2a_endpoint: None,
        web_bot_auth,
        max_delegation_depth: 0,
        updated_at: "2026-11-01T00:00:00Z".to_string(),
    };
    validate_discovery_document(&discovery, "example.com").unwrap();
    Setup {
        es256: load_signing_key(&kp.private_key_pem).unwrap(),
        kid,
        discovery,
    }
}

fn resolver(s: &Setup) -> TrustBundleResolver {
    TrustBundleResolver::new(&TrustBundle {
        agentpin_bundle_version: "0.1".to_string(),
        created_at: "2026-11-01T00:00:00Z".to_string(),
        documents: vec![s.discovery.clone()],
        revocations: vec![build_revocation_document("example.com")],
        expires_at: None,
        kid: None,
        signature: None,
    })
}

fn credential(s: &Setup, jkt: Option<&str>) -> String {
    let caps = vec![Capability::from("read:pages")];
    match jkt {
        Some(jkt) => issue_bound_credential(
            &s.es256,
            &s.kid,
            "example.com",
            AGENT_ID,
            None,
            caps,
            None,
            None,
            600,
            jkt,
        ),
        None => issue_credential(
            &s.es256,
            &s.kid,
            "example.com",
            AGENT_ID,
            None,
            caps,
            None,
            None,
            600,
        ),
    }
    .unwrap()
}

/// A signed request; `cover_auth` controls whether the signature covers
/// the Authorization field carrying the credential.
fn request(
    wba_key: &ed25519_dalek::SigningKey,
    signature_agent: &str,
    jwt: &str,
    cover_auth: bool,
) -> HttpRequest {
    let mut req = HttpRequest::new("GET", "https://shop.example/products")
        .unwrap()
        .header("Authorization", &format_authorization_header(jwt));
    let mut opts = SignOptions::default();
    if cover_auth {
        opts.components.push(Component::new("authorization"));
    }
    sign_request(&req, wba_key, signature_agent, &opts)
        .unwrap()
        .apply(&mut req);
    req
}

fn verify(
    s: &Setup,
    req: &HttpRequest,
    keys: &DirectoryKeyStore,
) -> Result<wba::BoundAgent, BindingFailure> {
    verify_bound_request(
        req,
        keys,
        &resolver(s),
        &mut KeyPinStore::new(),
        None,
        &VerifyOptions::default(),
        &VerifierConfig::default(),
    )
}

fn keys(url: &str, key: &ed25519_dalek::SigningKey) -> DirectoryKeyStore {
    let mut k = DirectoryKeyStore::new();
    k.insert(url, Directory::from_keys([&key.verifying_key()]))
        .unwrap();
    k
}

#[test]
fn bound_request_verifies_with_well_known_directory() {
    let s = setup(None);
    let wba_key = generate_signing_key();
    let url = well_known_directory("example.com");
    let jwt = credential(&s, Some(&wba::thumbprint(&wba_key.verifying_key())));
    let req = request(&wba_key, &url, &jwt, true);

    let bound = verify(&s, &req, &keys(&url, &wba_key)).expect("bound request verifies");
    assert_eq!(bound.agent.signature_agent, url);
    assert_eq!(bound.credential.agent_id.as_deref(), Some(AGENT_ID));
}

#[test]
fn discovery_can_vouch_for_a_hosted_directory() {
    let hosted = "https://bots.provider.example/keys/example-com";
    let s = setup(Some(WebBotAuth {
        signature_agents: vec![hosted.to_string()],
    }));
    let wba_key = generate_signing_key();
    let jwt = credential(&s, Some(&wba::thumbprint(&wba_key.verifying_key())));
    let req = request(&wba_key, hosted, &jwt, true);
    assert!(verify(&s, &req, &keys(hosted, &wba_key)).is_ok());

    // Listing a hosted directory replaces the well-known default.
    let wk = well_known_directory("example.com");
    let req = request(&wba_key, &wk, &jwt, true);
    assert!(matches!(
        verify(&s, &req, &keys(&wk, &wba_key)),
        Err(BindingFailure::Binding(_))
    ));
}

#[test]
fn binding_failures() {
    let s = setup(None);
    let wba_key = generate_signing_key();
    let url = well_known_directory("example.com");
    let store = keys(&url, &wba_key);
    let tp = wba::thumbprint(&wba_key.verifying_key());

    // Credential without cnf.
    let req = request(&wba_key, &url, &credential(&s, None), true);
    assert!(matches!(
        verify(&s, &req, &store),
        Err(BindingFailure::Binding(_))
    ));

    // cnf names a different key.
    let other = wba::thumbprint(&generate_signing_key().verifying_key());
    let req = request(&wba_key, &url, &credential(&s, Some(&other)), true);
    assert!(matches!(
        verify(&s, &req, &store),
        Err(BindingFailure::Binding(_))
    ));

    // Signature does not cover the Authorization field: the credential
    // could have been lifted from another request.
    let req = request(&wba_key, &url, &credential(&s, Some(&tp)), false);
    assert!(matches!(
        verify(&s, &req, &store),
        Err(BindingFailure::Binding(_))
    ));

    // Signature-Agent on a domain the issuer does not vouch for.
    let foreign = "https://attacker.example/.well-known/http-message-signatures-directory";
    let req = request(&wba_key, foreign, &credential(&s, Some(&tp)), true);
    assert!(matches!(
        verify(&s, &req, &keys(foreign, &wba_key)),
        Err(BindingFailure::Binding(_))
    ));

    // Credential swapped after signing: the covered Authorization changed.
    let mut req = request(&wba_key, &url, &credential(&s, Some(&tp)), true);
    let swapped = format_authorization_header(&credential(&s, Some(&tp)));
    for h in req.headers.iter_mut() {
        if h.0 == "Authorization" {
            h.1 = swapped.clone();
        }
    }
    assert!(matches!(
        verify(&s, &req, &store),
        Err(BindingFailure::Wba(WbaOutcome::Invalid(_)))
    ));

    // Forged credential: signed by a key the issuer does not publish.
    let rogue = setup(None);
    let req = request(&wba_key, &url, &credential(&rogue, Some(&tp)), true);
    assert!(matches!(
        verify(&s, &req, &store),
        Err(BindingFailure::Credential(_))
    ));
}

#[test]
fn invalid_discovery_web_bot_auth_rejected() {
    let mut s = setup(None);
    for agents in [vec![], vec!["http://insecure.example/dir".to_string()]] {
        s.discovery.web_bot_auth = Some(WebBotAuth {
            signature_agents: agents,
        });
        assert!(validate_discovery_document(&s.discovery, "example.com").is_err());
    }
}

#[test]
fn malformed_cnf_rejected_at_issuance() {
    let s = setup(None);
    let caps = vec![Capability::from("read:pages")];
    assert!(issue_bound_credential(
        &s.es256,
        &s.kid,
        "example.com",
        AGENT_ID,
        None,
        caps,
        None,
        None,
        600,
        "not-a-thumbprint",
    )
    .is_err());
}
