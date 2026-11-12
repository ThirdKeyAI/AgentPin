//! Shared Web Bot Auth vectors (testdata/web_bot_auth/vectors.json), also
//! run by the JavaScript, Python and Go SDKs.

use agentpin::httpsig::{self, Component, HttpRequest, Message, Param};
use agentpin::wba::{
    self, verify_directory_response, verify_request, Directory, DirectoryKeyStore, Jwk, PrivateKey,
    SignOptions, VerifyOptions, WbaOutcome,
};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/web_bot_auth/vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn request(v: &Value, with_sig: bool) -> HttpRequest {
    let mut req = HttpRequest::new(s(&v["method"]), s(&v["url"])).unwrap();
    for h in v["headers"].as_array().unwrap() {
        let name = s(&h[0]);
        if with_sig || !name.starts_with("Signature-I") && name != "Signature" {
            req = req.header(name, s(&h[1]));
        }
    }
    req
}

fn key(v: &Value, name: &str) -> PrivateKey {
    wba::load_signing_key(s(&v["keys"][name]["private_pem"])).unwrap()
}

#[test]
fn keyids_match_pem_and_jwk() {
    let v = vectors();
    for name in ["ed25519", "rsa"] {
        let k = &v["keys"][name];
        let from_pem = wba::thumbprint(&key(&v, name).public_key());
        let jwk: Jwk = serde_json::from_value(k["jwk"].clone()).unwrap();
        assert_eq!(from_pem, s(&k["keyid"]), "{}", name);
        assert_eq!(
            jwk.thumbprint().as_deref(),
            Some(s(&k["keyid"])),
            "{}",
            name
        );
    }
}

#[test]
fn request_vectors_verify_and_reproduce() {
    let v = vectors();
    let opts = VerifyOptions {
        now: Some(1735689700),
        max_validity_secs: i64::MAX,
        ..Default::default()
    };
    for t in v["requests"].as_array().unwrap() {
        let k = key(&v, s(&t["key"]));
        let mut store = DirectoryKeyStore::new();
        store
            .insert(
                s(&t["signature_agent_url"]),
                Directory::from_keys([&k.public_key()]),
            )
            .unwrap();
        let req = request(t, true);
        assert!(
            matches!(verify_request(&req, &store, &opts), WbaOutcome::Verified(_)),
            "{}",
            t["name"]
        );

        // Re-sign over the same base: Ed25519 reproduces the signature;
        // RSA-PSS is randomized, so check that ours verifies.
        let parsed = httpsig::parse_signatures(&req.headers).unwrap();
        let p = &parsed[0].params;
        let params = [
            Param::Created(p.created.unwrap()),
            Param::KeyId(p.keyid.clone().unwrap()),
            Param::Alg(p.alg.clone().unwrap()),
            Param::Expires(p.expires.unwrap()),
            Param::Nonce(p.nonce.clone().unwrap()),
            Param::Tag(p.tag.clone().unwrap()),
        ];
        let unsigned = request(t, false);
        let f = httpsig::sign(
            Message::Request(&unsigned),
            &parsed[0].label,
            &parsed[0].components,
            &params,
            &k,
        )
        .unwrap();
        assert_eq!(f.signature_input, s(&t["headers"][1][1]), "{}", t["name"]);
        if t["reproducible"].as_bool().unwrap() {
            assert_eq!(f.signature, s(&t["headers"][2][1]), "{}", t["name"]);
        }
        let ours = unsigned
            .header("Signature-Input", &f.signature_input)
            .header("Signature", &f.signature);
        assert!(matches!(
            verify_request(&ours, &store, &opts),
            WbaOutcome::Verified(_)
        ));
    }
}

#[test]
fn directory_vector() {
    let v = vectors();
    let d = &v["directory"];
    let headers: Vec<(String, String)> = d["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| (s(&h[0]).to_string(), s(&h[1]).to_string()))
        .collect();
    let proven = verify_directory_response(
        s(&d["body"]).as_bytes(),
        &headers,
        s(&d["authority"]),
        1735689700,
        60,
    )
    .unwrap();
    assert_eq!(proven.keys.len(), 1);
}

#[test]
fn rfc9421_and_query_param_and_digest() {
    let v = vectors();
    let b = &v["rfc9421_b26"];
    let mut req = HttpRequest::new(s(&b["method"]), s(&b["url"])).unwrap();
    for h in b["headers"].as_array().unwrap() {
        req = req.header(s(&h[0]), s(&h[1]));
    }
    let signed = req
        .header("Signature-Input", s(&b["signature_input"]))
        .header("Signature", s(&b["signature"]));
    let parsed = httpsig::parse_signatures(&signed.headers).unwrap();
    httpsig::verify(
        Message::Request(&signed),
        &parsed[0],
        &key(&v, "ed25519").public_key(),
    )
    .unwrap();

    let q = &v["query_param"];
    let qreq = HttpRequest::new("GET", s(&q["url"])).unwrap();
    for case in q["values"].as_array().unwrap() {
        let c = Component::query_param(s(&case[0]));
        assert_eq!(c.query_name.as_deref(), Some(s(&case[1])));
        let f =
            httpsig::sign(Message::Request(&qreq), "q", &[c], &[], &key(&v, "ed25519")).unwrap();
        let signed = qreq
            .clone()
            .header("Signature-Input", &f.signature_input)
            .header("Signature", &f.signature);
        let parsed = httpsig::parse_signatures(&signed.headers).unwrap();
        let base = parsed[0].signature_base(Message::Request(&signed)).unwrap();
        let line = format!(
            "\"@query-param\";name=\"{}\": {}\n",
            s(&case[1]),
            s(&case[2])
        );
        assert!(base.starts_with(&line), "{}", base);
    }
    for name in q["errors"].as_array().unwrap() {
        let c = Component::query_param(s(name));
        assert!(
            httpsig::sign(Message::Request(&qreq), "q", &[c], &[], &key(&v, "ed25519")).is_err()
        );
    }

    let d = &v["content_digest"];
    assert_eq!(
        httpsig::content_digest(s(&d["body"]).as_bytes()),
        s(&d["value"])
    );
}

#[test]
fn rsa_signing_roundtrip_and_alg() {
    let v = vectors();
    let k = key(&v, "rsa");
    assert_eq!(k.alg(), "rsa-pss-sha512");
    let agent = "https://agent.test/.well-known/http-message-signatures-directory";
    let mut req = HttpRequest::new("GET", "https://origin.test/x").unwrap();
    wba::sign_request(&req, &k, agent, &SignOptions::default())
        .unwrap()
        .apply(&mut req);
    let mut store = DirectoryKeyStore::new();
    store
        .insert(agent, Directory::from_keys([&k.public_key()]))
        .unwrap();
    assert!(matches!(
        verify_request(&req, &store, &VerifyOptions::default()),
        WbaOutcome::Verified(_)
    ));
    // The same keyid published as Ed25519 cannot exist, but a mismatched
    // alg parameter must fail even with the right key.
    let tampered: Vec<(String, String)> = req
        .headers
        .iter()
        .map(|(n, val)| (n.clone(), val.replace("rsa-pss-sha512", "ed25519")))
        .collect();
    let mut bad = req.clone();
    bad.headers = tampered;
    assert!(matches!(
        verify_request(&bad, &store, &VerifyOptions::default()),
        WbaOutcome::Invalid(_)
    ));
}
