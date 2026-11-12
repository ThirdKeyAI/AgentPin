"""Web Bot Auth profile: signing, verification outcomes, directories."""

import base64
import json
import time
from pathlib import Path

import pytest

from agentpin import httpsig, wba
from agentpin.httpsig import Component, HttpRequest
from agentpin.jwt import base64url_decode, base64url_encode
from agentpin.nonce import InMemoryNonceStore
from agentpin.types import AgentPinError
from agentpin.wba import (
    MAX_DIRECTORY_KEYS,
    MAX_VALIDITY_SECS,
    TAG,
    Directory,
    DirectoryKeyStore,
    Jwk,
    SignOptions,
    VerifyOptions,
    WbaOutcome,
)

RFC_ED25519_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n"
    "-----END PRIVATE KEY-----\n"
)
RFC_KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
RFC_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
AGENT = "https://signature-agent.test"


def rfc_key():
    return wba.load_signing_key(RFC_ED25519_PEM)


def gen():
    return wba.generate_signing_key()


def store_with(key, url=AGENT):
    store = DirectoryKeyStore()
    store.insert(url, Directory.from_keys([key.public_key()]))
    return store


def signed_request(key, opts=None, url="https://origin.example/path?q=1"):
    req = HttpRequest("GET", url)
    wba.sign_request(req, key, AGENT, opts or SignOptions()).apply(req)
    return req


def replace_header(req, name, value):
    return HttpRequest(req.method, req.url, [(n, value if n == name else v) for n, v in req.headers])


def test_thumbprint_matches_draft_vector():
    key = rfc_key().public_key()
    assert wba.thumbprint(key) == RFC_KEYID
    jwk = Jwk.from_public_key(key)
    assert jwk.x == RFC_X and jwk.kid == RFC_KEYID
    assert jwk.public_key() == key


def test_draft_e21_dictionary_signature_agent():
    req = HttpRequest("GET", "https://example.com/", [("Signature-Agent", 'agent2="https://signature-agent.test"')])
    params = [
        ("created", 1735689600),
        ("keyid", RFC_KEYID),
        ("alg", "ed25519"),
        ("expires", 4889289600),
        ("nonce", "n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="),
        ("tag", TAG),
    ]
    f = httpsig.sign(
        req, "sig2", [Component("@authority"), Component.keyed("signature-agent", "agent2")], params, rfc_key()
    )
    assert f.signature == (
        "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:"
    )
    s = req.header("Signature-Input", f.signature_input).header("Signature", f.signature)
    store = store_with(rfc_key())
    out = wba.verify_request(s, store, VerifyOptions(now=1735689700, max_validity_secs=2**63 - 1))
    assert out.verified and out.agent is not None
    assert out.agent.signature_agent == "https://signature-agent.test/"
    assert out.agent.keyid == RFC_KEYID and out.agent.label == "sig2"
    # The default 24 h ceiling rejects the vector's long window.
    assert wba.verify_request(s, store, VerifyOptions(now=1735689700)).invalid


def test_draft_e22_legacy_signature_agent():
    req = HttpRequest(
        "GET",
        "https://example.com/",
        [
            ("Signature-Agent", '"https://signature-agent.test"'),
            (
                "Signature-Input",
                'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5Sol'
                'qXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZY'
                'adIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"',
            ),
            (
                "Signature",
                "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
            ),
        ],
    )
    store = store_with(rfc_key())
    assert wba.verify_request(req, store, VerifyOptions(now=1735689700)).verified
    strict = VerifyOptions(now=1735689700, accept_legacy_signature_agent=False)
    assert wba.verify_request(req, store, strict).invalid


def test_draft_e23_directory_response():
    body = (
        '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s","use":"sig"}]}' % (RFC_KEYID, RFC_X)
    ).encode()
    assert Directory.from_keys([rfc_key().public_key()]).to_json() == body
    headers = wba.sign_directory_response(body, "signature-agent.test", [rfc_key()], 1735689600, MAX_VALIDITY_SECS)
    assert headers[0][1] == "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"
    assert headers[1][1].startswith("binding0=")
    vector = [
        ("Content-Digest", "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"),
        (
            "Signature-Input",
            'binding=("@authority";req "content-digest");created=1735689600;expires=4889289600;'
            'keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";tag="http-message-signatures-directory"',
        ),
        (
            "Signature",
            "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:",
        ),
    ]
    assert len(wba.verify_directory_response(body, vector, "signature-agent.test", 1735689700, 60).keys) == 1
    # Re-served under another authority: the proof does not carry over.
    assert wba.verify_directory_response(body, vector, "evil.test", 1735689700, 60).keys == []
    # Swapped body: digest mismatch.
    with pytest.raises(AgentPinError):
        wba.verify_directory_response(b'{"keys":[]}', vector, "signature-agent.test", 1735689700, 60)
    # Our own signing round-trips.
    assert len(wba.verify_directory_response(body, headers, "signature-agent.test", 1735689700, 60).keys) == 1
    # Future-dated proofs are rejected.
    assert wba.verify_directory_response(body, headers, "signature-agent.test", 1735680000, 60).keys == []
    with pytest.raises(AgentPinError):
        wba.sign_directory_response(body, "a.test", [rfc_key()], 0, MAX_VALIDITY_SECS + 1)


def test_sign_and_verify_roundtrip():
    key = gen()
    req = signed_request(key)
    sigs = httpsig.parse_signatures(req.headers)
    assert sigs[0].params.tag == TAG
    assert sigs[0].params.nonce is not None
    assert len(base64.b64decode(sigs[0].params.nonce)) == 64
    httpsig.verify(req, sigs[0], key.public_key())
    out = wba.verify_request(req, store_with(key))
    assert out.verified and out.agent is not None
    assert out.agent.covers(Component("@method")) and out.agent.covers(Component("@path"))
    assert out.agent.expires - out.agent.created == 300
    assert req.headers[-3] == ("Signature-Agent", 'sig1="https://signature-agent.test/"')
    assert httpsig.combined_field(req.headers, "signature-input").startswith(
        'sig1=("@authority" "signature-agent";key="sig1" "@method" "@path");created='
    )


def test_outcomes_distinguish_invalid_and_unverified():
    key = gen()
    req = signed_request(key)
    # Unknown directory: unverified.
    assert wba.verify_request(req, DirectoryKeyStore()).unverified
    # Directory resolved without the key: unverified.
    assert wba.verify_request(req, store_with(gen())).unverified
    # Unsigned request: unverified.
    assert wba.verify_request(HttpRequest("GET", "https://origin.example/"), store_with(key)).unverified
    # Expired: invalid.
    old = signed_request(key, SignOptions(created=int(time.time()) - 10_000))
    assert wba.verify_request(old, store_with(key)).invalid
    # Future-dated: invalid.
    future = signed_request(key, SignOptions(created=int(time.time()) + 10_000))
    assert wba.verify_request(future, store_with(key)).invalid
    # Path changed after signing: invalid.
    moved = HttpRequest(req.method, "https://origin.example/other", list(req.headers))
    assert wba.verify_request(moved, store_with(key)).invalid
    # Method changed after signing: invalid.
    posted = HttpRequest("POST", req.url, list(req.headers))
    assert wba.verify_request(posted, store_with(key)).invalid
    # Signature bytes tampered: invalid.
    sig = httpsig.combined_field(req.headers, "signature")
    tampered = replace_header(req, "Signature", sig[:10] + ("A" if sig[10] != "A" else "B") + sig[11:])
    assert wba.verify_request(tampered, store_with(key)).invalid
    # Malformed Signature-Input: invalid.
    assert wba.verify_request(replace_header(req, "Signature-Input", "sig1=(oops"), store_with(key)).invalid


def test_required_components_and_unsupported_alg():
    key = gen()
    req = signed_request(key)
    opts = VerifyOptions(required_components=[Component("content-digest")])
    out = wba.verify_request(req, store_with(key), opts)
    assert out.invalid and "content-digest" in (out.reason or "")
    now = int(time.time())
    base = HttpRequest("GET", "https://origin.example/", [("Signature-Agent", 'sig1="https://signature-agent.test"')])
    f = httpsig.sign(
        base,
        "sig1",
        [Component("@authority"), Component.keyed("signature-agent", "sig1")],
        [("created", now), ("expires", now + 60), ("keyid", wba.thumbprint(key.public_key())), ("alg", "hmac-sha256"),
         ("tag", TAG)],
        key,
    )
    s = base.header("Signature-Input", f.signature_input).header("Signature", f.signature)
    assert wba.verify_request(s, store_with(key)) == WbaOutcome.invalid_because("unsupported alg 'hmac-sha256'")


def test_signature_without_authority_or_tag():
    key = gen()
    now = int(time.time())
    base = HttpRequest("GET", "https://origin.example/", [("Signature-Agent", 'sig1="https://signature-agent.test"')])
    params = [("created", now), ("expires", now + 60), ("keyid", wba.thumbprint(key.public_key())), ("tag", TAG)]
    f = httpsig.sign(base, "sig1", [Component.keyed("signature-agent", "sig1")], params, key)
    s = base.header("Signature-Input", f.signature_input).header("Signature", f.signature)
    assert wba.verify_request(s, store_with(key)).invalid
    # A non-WBA signature is ignored: unverified.
    f = httpsig.sign(base, "sig1", [Component("@authority")], params[:3], key)
    s = base.header("Signature-Input", f.signature_input).header("Signature", f.signature)
    assert wba.verify_request(s, store_with(key)).unverified


def test_key_is_bound_to_its_directory():
    key = gen()
    req = HttpRequest("GET", "https://origin.example/")
    wba.sign_request(req, key, "https://victim.example/.well-known/http-message-signatures-directory").apply(req)
    # The verifier learned this key from AGENT, not from victim.example.
    assert wba.verify_request(req, store_with(key)).unverified


def test_rejects_signature_agent_problems():
    key = gen()
    store = store_with(key)

    # Member swapped after signing: lookup happens under the new URL, so with
    # no directory there the request is unverified, and with the same key
    # there it is invalid.
    req = replace_header(signed_request(key), "Signature-Agent", 'sig1="https://other.test"')
    assert wba.verify_request(req, store).unverified
    both = store.copy()
    both.insert("https://other.test", Directory.from_keys([key.public_key()]))
    assert wba.verify_request(req, both).invalid

    # Two covered members: ambiguous attribution.
    now = int(time.time())
    two = HttpRequest("GET", "https://origin.example/", [("Signature-Agent", 'a="https://a.test", b="https://b.test"')])
    f = httpsig.sign(
        two,
        "a",
        [Component("@authority"), Component.keyed("signature-agent", "a"), Component.keyed("signature-agent", "b")],
        [("created", now), ("expires", now + 60), ("keyid", wba.thumbprint(key.public_key())), ("tag", TAG)],
        key,
    )
    two = two.header("Signature-Input", f.signature_input).header("Signature", f.signature)
    assert wba.verify_request(two, store).invalid

    plain = HttpRequest("GET", "https://origin.example/")
    # Non-https Signature-Agent is refused at signing time.
    with pytest.raises(AgentPinError):
        wba.sign_request(plain, key, "http://insecure.test")
    # Validity above 24 h is refused at signing time.
    with pytest.raises(AgentPinError):
        wba.sign_request(plain, key, AGENT, SignOptions(validity_secs=MAX_VALIDITY_SECS + 1))
    with pytest.raises(AgentPinError):
        wba.sign_request(plain, key, AGENT, SignOptions(validity_secs=0))
    # Label collision with an existing Signature-Agent member.
    with pytest.raises(AgentPinError):
        wba.sign_request(plain.header("Signature-Agent", 'sig1="https://a.test"'), key, AGENT)


def test_signature_agent_alongside_other_members():
    key = gen()
    req = HttpRequest("GET", "https://origin.example/", [("Signature-Agent", 'other="https://a.test"')])
    wba.sign_request(req, key, AGENT).apply(req)
    assert wba.verify_request(req, store_with(key)).verified


def test_legacy_signing_roundtrip():
    key = gen()
    opts = SignOptions(legacy_signature_agent=True)
    req = signed_request(key, opts)
    assert httpsig.combined_field(req.headers, "signature-agent").startswith('"')
    assert wba.verify_request(req, store_with(key)).verified
    assert wba.verify_request(req, store_with(key), VerifyOptions(accept_legacy_signature_agent=False)).invalid
    existing = HttpRequest("GET", "https://origin.example/", [("Signature-Agent", 'a="https://a.test"')])
    with pytest.raises(AgentPinError):
        wba.sign_request(existing, key, AGENT, opts)


def test_member_with_parameters_is_rejected():
    with pytest.raises(wba._Reject):
        wba._signature_agent_member([("Signature-Agent", 'sig1="https://a.test";type=jwks_uri')], "sig1", False)


def test_normalizes_identifiers():
    assert wba.normalize_signature_agent("HTTPS://Agent.Example:443/dir?x=1#f") == "https://agent.example/dir"
    for bad in ["http://agent.example", "https://u:p@agent.example", "/relative"]:
        with pytest.raises(AgentPinError):
            wba.normalize_signature_agent(bad)


def test_directory_parse_skips_foreign_keys_and_honors_validity():
    key = gen()
    jwk = Jwk.from_public_key(key.public_key())
    jwk.nbf, jwk.exp = 100, 200
    rsa_short = {"kty": "RSA", "n": "AQAB", "e": "AQAB"}
    doc = {
        "keys": [
            {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
            {"kty": "OKP", "crv": "Ed25519", "x": "short"},
            {"kty": "OKP", "crv": "Ed25519", "x": RFC_X, "nbf": 1.5},
            rsa_short,
            "not an object",
            jwk.to_dict(),
        ]
    }
    d = Directory.parse(json.dumps(doc).encode())
    assert len(d.keys) == 1
    tp = wba.thumbprint(key.public_key())
    assert wba.find_key(d, tp, 150, 0) is not None
    assert wba.find_key(d, tp, 50, 0) is None
    assert wba.find_key(d, tp, 250, 0) is None
    with pytest.raises(AgentPinError):
        Directory.parse(json.dumps({"keys": [{}] * (MAX_DIRECTORY_KEYS + 1)}).encode())
    for bad in [b"[]", b"{}", b"not json", b'{"keys": {}}']:
        with pytest.raises(AgentPinError):
            Directory.parse(bad)


def test_rsa_jwk_requires_minimal_encodings():
    vectors = Path(__file__).resolve().parents[2] / "testdata" / "web_bot_auth" / "vectors.json"
    rsa_jwk = Jwk.from_dict(json.loads(vectors.read_text())["keys"]["rsa"]["jwk"])
    n = base64url_decode(rsa_jwk.n)
    assert rsa_jwk.thumbprint() is not None
    padded = Jwk("RSA", n=base64url_encode(b"\x00" + n), e="AQAB")
    assert padded.thumbprint() is None
    assert Jwk("RSA", n=rsa_jwk.n, e=base64url_encode(b"\x00\x01\x00\x01")).thumbprint() is None
    assert Jwk("RSA", n=rsa_jwk.n, e=base64url_encode(b"\x01\x00\x00\x00\x01")).thumbprint() is None
    assert Jwk("RSA", n=rsa_jwk.n + "=", e="AQAB").thumbprint() is None


def test_pem_roundtrip():
    key = gen()
    pem = wba.signing_key_to_pem(key)
    assert wba.load_signing_key(pem).public_key() == key.public_key()
    with pytest.raises(AgentPinError):
        wba.load_signing_key("not a key")


def test_nonce_store_rejects_replays():
    key = gen()
    store = store_with(key)
    opts = VerifyOptions(nonce_store=InMemoryNonceStore())
    req = signed_request(key)
    assert wba.verify_request(req, store, opts).verified
    assert wba.verify_request(req, store, opts) == WbaOutcome.invalid_because("nonce replayed")
    # A fresh signature is fine; one without a nonce is not.
    assert wba.verify_request(signed_request(key), store, opts).verified
    assert wba.verify_request(signed_request(key, SignOptions(nonce=False)), store, opts).invalid
    # Forged signatures never reach the store.
    forged = signed_request(key)
    forged = HttpRequest(forged.method, "https://origin.example/elsewhere", list(forged.headers))
    assert wba.verify_request(forged, store, opts) == WbaOutcome.invalid_because("signature verification failed")
    restored = HttpRequest(forged.method, "https://origin.example/path?q=1", list(forged.headers))
    assert wba.verify_request(restored, store, opts).verified


def test_nonce_store_ttl_and_key():
    seen = []

    class Recording(InMemoryNonceStore):
        def check_and_record(self, nonce, ttl_seconds):
            seen.append((nonce, ttl_seconds))
            return True

    key = gen()
    now = int(time.time())
    req = signed_request(key, SignOptions(created=now, validity_secs=100))
    opts = VerifyOptions(now=now, nonce_store=Recording())
    assert wba.verify_request(req, store_with(key), opts).verified
    nonce = httpsig.parse_signatures(req.headers)[0].params.nonce
    assert seen == [(f"{wba.thumbprint(key.public_key())} {nonce}", 160)]

    class Broken(InMemoryNonceStore):
        def check_and_record(self, nonce, ttl_seconds):
            raise RuntimeError("down")

    out = wba.verify_request(req, store_with(key), VerifyOptions(now=now, nonce_store=Broken()))
    assert out.invalid and out.reason == "nonce store failed: down"
