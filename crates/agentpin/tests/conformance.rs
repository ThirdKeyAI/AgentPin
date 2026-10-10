//! Cross-SDK conformance vectors from `testdata/conformance/vectors.json`.
//! The same file is checked by the Go, JavaScript and Python suites.

use std::path::PathBuf;

use agentpin::a2a::verify_agentpin_extension;
use agentpin::credential::issue_credential;
use agentpin::crypto::{
    domain_separated_input, generate_key_pair, load_signing_key, load_verifying_key,
};
use agentpin::discovery::validate_discovery_document;
use agentpin::error::ErrorCode;
use agentpin::jwk::verifying_key_to_jwk;
use agentpin::pinning::KeyPinStore;
use agentpin::types::a2a::A2aAgentCard;
use agentpin::types::capability::Capability;
use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use agentpin::verification::{verify_credential_offline, VerifierConfig};
use serde_json::Value;

const AGENT: &str = "urn:agentpin:example.com:test-agent";

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/conformance")
}

fn read(name: &str) -> String {
    std::fs::read_to_string(dir().join(name)).unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(&read("vectors.json")).unwrap()
}

fn discovery() -> DiscoveryDocument {
    serde_json::from_str(&read("discovery.json")).unwrap()
}

fn code(name: &str) -> ErrorCode {
    serde_json::from_value(Value::String(name.to_string())).unwrap()
}

#[test]
fn malformed_credentials_are_rejected() {
    let v = vectors();
    for c in v["credentials"].as_array().unwrap() {
        let r = verify_credential_offline(
            c["jwt"].as_str().unwrap(),
            &discovery(),
            None,
            &mut KeyPinStore::new(),
            None,
            &VerifierConfig::default(),
        );
        assert!(!r.valid, "{} accepted", c["name"]);
        assert_eq!(
            r.error_code,
            Some(code(c["error_code"].as_str().unwrap())),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn case_variant_issuer_hits_existing_pin() {
    let v = &vectors()["case_variant_issuer"];
    let disc = discovery();
    let mut store = KeyPinStore::new();
    store.check_and_pin("example.com", &disc.public_keys[0]);

    let kp = generate_key_pair().unwrap();
    let sk = load_signing_key(&kp.private_key_pem).unwrap();
    let vk = load_verifying_key(&kp.public_key_pem).unwrap();
    let issuer = v["issuer"].as_str().unwrap();
    let mut evil = disc.clone();
    evil.entity = issuer.to_string();
    evil.public_keys = vec![verifying_key_to_jwk(&vk, "evil-key")];
    let jwt = issue_credential(
        &sk,
        "evil-key",
        issuer,
        AGENT,
        None,
        vec![Capability::from("read:data")],
        None,
        None,
        3600,
    )
    .unwrap();
    let r = verify_credential_offline(
        &jwt,
        &evil,
        None,
        &mut store,
        None,
        &VerifierConfig::default(),
    );
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(code(v["error_code"].as_str().unwrap())));
}

#[test]
fn revocation_with_wrong_field_names_is_rejected() {
    // The typed Rust model rejects the document at parse time, which is the
    // fail-closed outcome the vector requires.
    let v = &vectors()["revocation_wrong_field_names"];
    let parsed: Result<RevocationDocument, _> = serde_json::from_value(v["document"].clone());
    assert!(parsed.is_err());
}

#[test]
fn invalid_revocation_endpoints_are_rejected() {
    for url in vectors()["invalid_revocation_endpoints"]
        .as_array()
        .unwrap()
    {
        let mut d = discovery();
        d.revocation_endpoint = Some(url.as_str().unwrap().to_string());
        assert!(
            validate_discovery_document(&d, "example.com").is_err(),
            "{url} accepted"
        );
    }
}

#[test]
fn agent_cards_verify_as_expected() {
    for c in vectors()["agent_cards"].as_array().unwrap() {
        let card: A2aAgentCard = serde_json::from_value(c["card"].clone()).unwrap();
        assert_eq!(
            verify_agentpin_extension(&card).is_ok(),
            c["valid"].as_bool().unwrap(),
            "{}",
            c["name"]
        );
    }
}

#[test]
fn domain_separated_input_layout() {
    let v = &vectors()["domain_separated_input"];
    let fields: Vec<Vec<u8>> = v["fields_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| hex_decode(h.as_str().unwrap()))
        .collect();
    let refs: Vec<&[u8]> = fields.iter().map(|f| f.as_slice()).collect();
    let got = domain_separated_input(v["context"].as_str().unwrap(), &refs);
    assert_eq!(got, hex_decode(v["expected_hex"].as_str().unwrap()));
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
