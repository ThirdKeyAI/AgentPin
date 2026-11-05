"""Shared Web Bot Auth vectors (testdata/web_bot_auth/vectors.json at the
repository root), also run by the Rust, JavaScript and Go suites."""

import json
from pathlib import Path

import pytest

from agentpin import httpsig, wba
from agentpin.httpsig import Component, HttpRequest
from agentpin.types import AgentPinError
from agentpin.wba import Directory, DirectoryKeyStore, Jwk, SignOptions, VerifyOptions

VECTORS = json.loads(
    (Path(__file__).resolve().parents[2] / "testdata" / "web_bot_auth" / "vectors.json").read_text()
)
NOW = 1735689700
NO_CEILING = VerifyOptions(now=NOW, max_validity_secs=2**63 - 1)


def request(v, with_sig):
    headers = [
        (h[0], h[1])
        for h in v["headers"]
        if with_sig or (not h[0].startswith("Signature-I") and h[0] != "Signature")
    ]
    return HttpRequest(v["method"], v["url"], headers)


def key(name):
    return wba.load_signing_key(VECTORS["keys"][name]["private_pem"])


@pytest.mark.parametrize("name", ["ed25519", "rsa"])
def test_keyids_match_pem_and_jwk(name):
    k = VECTORS["keys"][name]
    assert wba.thumbprint(key(name).public_key()) == k["keyid"]
    assert Jwk.from_dict(k["jwk"]).thumbprint() == k["keyid"]


@pytest.mark.parametrize("t", VECTORS["requests"], ids=lambda t: t["name"])
def test_request_vectors_verify_and_reproduce(t):
    k = key(t["key"])
    store = DirectoryKeyStore()
    store.insert(t["signature_agent_url"], Directory.from_keys([k.public_key()]))
    req = request(t, True)
    outcome = wba.verify_request(req, store, NO_CEILING)
    assert outcome.verified, outcome.reason

    # Re-sign over the same base: Ed25519 reproduces the signature; RSA-PSS
    # is randomized, so check that ours verifies.
    parsed = httpsig.parse_signatures(req.headers)[0]
    p = parsed.params
    params = [
        ("created", p.created),
        ("keyid", p.keyid),
        ("alg", p.alg),
        ("expires", p.expires),
        ("nonce", p.nonce),
        ("tag", p.tag),
    ]
    unsigned = request(t, False)
    f = httpsig.sign(unsigned, parsed.label, parsed.components, params, k)
    assert f.signature_input == t["headers"][1][1]
    if t["reproducible"]:
        assert f.signature == t["headers"][2][1]
    ours = unsigned.header("Signature-Input", f.signature_input).header("Signature", f.signature)
    assert wba.verify_request(ours, store, NO_CEILING).verified


def test_directory_vector():
    d = VECTORS["directory"]
    headers = [(h[0], h[1]) for h in d["headers"]]
    proven = wba.verify_directory_response(d["body"].encode(), headers, d["authority"], NOW, 60)
    assert len(proven.keys) == 1
    # Our serializer reproduces the body.
    assert Directory.from_keys([key("ed25519").public_key()]).to_json() == d["body"].encode()


def test_rfc9421_b26():
    b = VECTORS["rfc9421_b26"]
    req = HttpRequest(b["method"], b["url"], [(h[0], h[1]) for h in b["headers"]])
    signed = req.header("Signature-Input", b["signature_input"]).header("Signature", b["signature"])
    parsed = httpsig.parse_signatures(signed.headers)
    httpsig.verify(signed, parsed[0], key("ed25519").public_key())


def test_query_param_values_and_errors():
    q = VECTORS["query_param"]
    qreq = HttpRequest("GET", q["url"])
    k = key("ed25519")
    for name, encoded, value in q["values"]:
        c = Component.query_param(name)
        assert c.query_name == encoded
        f = httpsig.sign(qreq, "q", [c], [], k)
        signed = qreq.header("Signature-Input", f.signature_input).header("Signature", f.signature)
        parsed = httpsig.parse_signatures(signed.headers)
        base = parsed[0].signature_base(signed)
        assert base.startswith(f'"@query-param";name="{encoded}": {value}\n'), base
    for name in q["errors"]:
        with pytest.raises(AgentPinError):
            httpsig.sign(qreq, "q", [Component.query_param(name)], [], k)


def test_content_digest():
    d = VECTORS["content_digest"]
    assert httpsig.content_digest(d["body"].encode()) == d["value"]


def test_rsa_signing_roundtrip_and_alg():
    k = key("rsa")
    assert k.alg == "rsa-pss-sha512"
    agent = "https://agent.test/.well-known/http-message-signatures-directory"
    req = HttpRequest("GET", "https://origin.test/x")
    wba.sign_request(req, k, agent, SignOptions()).apply(req)
    store = DirectoryKeyStore()
    store.insert(agent, Directory.from_keys([k.public_key()]))
    assert wba.verify_request(req, store).verified
    # A mismatched alg parameter fails even with the right key.
    bad = HttpRequest(req.method, req.url, [(n, v.replace("rsa-pss-sha512", "ed25519")) for n, v in req.headers])
    assert wba.verify_request(bad, store).invalid
