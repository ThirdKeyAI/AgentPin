"""End-to-end Web Bot Auth flow: an agent signs a request with its WBA key
and carries a cnf-bound AgentPin credential; the origin verifies the
signature, the credential and the binding between them."""

import pytest

from agentpin import wba
from agentpin.capability import Capability
from agentpin.credential import issue_bound_credential, issue_credential
from agentpin.crypto import generate_key_id, generate_key_pair
from agentpin.discovery import build_discovery_document, validate_discovery_document
from agentpin.httpsig import Component, HttpRequest
from agentpin.jwk import pem_to_jwk
from agentpin.jwt import MalformedCredentialError, validate_claims
from agentpin.pinning import KeyPinStore
from agentpin.transport import http_format_authorization_header
from agentpin.types import AgentPinError
from agentpin.verification import verify_credential_with_resolver
from agentpin.wba import BindingFailure, Directory, DirectoryKeyStore, SignOptions, well_known_directory

AGENT_ID = "urn:agentpin:example.com:crawler"


class Setup:
    def __init__(self, web_bot_auth=None):
        self.private_pem, public_pem = generate_key_pair()
        self.kid = generate_key_id(public_pem)
        self.discovery = build_discovery_document(
            "example.com",
            "maker",
            [pem_to_jwk(public_pem, self.kid)],
            [{"agent_id": AGENT_ID, "name": "Crawler", "capabilities": ["read:*"], "status": "active"}],
            0,
            "2026-11-01T00:00:00Z",
        )
        if web_bot_auth is not None:
            self.discovery["web_bot_auth"] = web_bot_auth
        validate_discovery_document(self.discovery, "example.com")

    # Resolver interface.
    def resolve_discovery(self, domain):
        if domain != "example.com":
            raise AgentPinError("DISCOVERY_FETCH_FAILED", "unknown domain")
        return self.discovery

    def resolve_revocation(self, domain, discovery):
        return None

    def credential(self, jkt=None):
        caps = [Capability("read:pages")]
        if jkt is None:
            return issue_credential(self.private_pem, self.kid, "example.com", AGENT_ID, None, caps, None, None, 600)
        return issue_bound_credential(
            self.private_pem, self.kid, "example.com", AGENT_ID, None, caps, None, None, 600, jkt
        )


def request(wba_key, signature_agent, jwt, cover_auth=True):
    auth = http_format_authorization_header(jwt)
    req = HttpRequest("GET", "https://shop.example/products", [("Authorization", auth)])
    opts = SignOptions()
    if cover_auth:
        opts.components.append(Component("authorization"))
    wba.sign_request(req, wba_key, signature_agent, opts).apply(req)
    return req


def keys(url, key):
    k = DirectoryKeyStore()
    k.insert(url, Directory.from_keys([key.public_key()]))
    return k


def verify(s, req, store):
    return wba.verify_bound_request(req, store, s, KeyPinStore())


def failure(s, req, store):
    with pytest.raises(BindingFailure) as e:
        verify(s, req, store)
    return e.value


def test_bound_request_verifies_with_well_known_directory():
    s = Setup()
    key = wba.generate_signing_key()
    url = well_known_directory("example.com")
    req = request(key, url, s.credential(wba.thumbprint(key.public_key())))
    bound = verify(s, req, keys(url, key))
    assert bound.agent.signature_agent == url
    assert bound.credential.agent_id == AGENT_ID


def test_bound_request_with_rsa_key():
    s = Setup()
    import json
    from pathlib import Path

    v = json.loads((Path(__file__).resolve().parents[2] / "testdata" / "web_bot_auth" / "vectors.json").read_text())
    key = wba.load_signing_key(v["keys"]["rsa"]["private_pem"])
    url = well_known_directory("example.com")
    req = request(key, url, s.credential(wba.thumbprint(key.public_key())))
    assert verify(s, req, keys(url, key)).agent.keyid == v["keys"]["rsa"]["keyid"]


def test_discovery_can_vouch_for_a_hosted_directory():
    hosted = "https://bots.provider.example/keys/example-com"
    s = Setup({"signature_agents": [hosted]})
    key = wba.generate_signing_key()
    jwt = s.credential(wba.thumbprint(key.public_key()))
    assert verify(s, request(key, hosted, jwt), keys(hosted, key))
    # Listing a hosted directory replaces the well-known default.
    wk = well_known_directory("example.com")
    assert failure(s, request(key, wk, jwt), keys(wk, key)).kind == BindingFailure.BINDING


def test_binding_failures():
    s = Setup()
    key = wba.generate_signing_key()
    url = well_known_directory("example.com")
    store = keys(url, key)
    tp = wba.thumbprint(key.public_key())

    # Credential without cnf.
    assert failure(s, request(key, url, s.credential()), store).kind == BindingFailure.BINDING
    # cnf names a different key.
    other = wba.thumbprint(wba.generate_signing_key().public_key())
    assert failure(s, request(key, url, s.credential(other)), store).kind == BindingFailure.BINDING
    # Signature does not cover the Authorization field.
    assert failure(s, request(key, url, s.credential(tp), cover_auth=False), store).kind == BindingFailure.BINDING
    # Signature-Agent on a domain the issuer does not vouch for.
    foreign = "https://attacker.example/.well-known/http-message-signatures-directory"
    assert failure(s, request(key, foreign, s.credential(tp)), keys(foreign, key)).kind == BindingFailure.BINDING
    # Credential swapped after signing: the covered Authorization changed.
    req = request(key, url, s.credential(tp))
    swapped = http_format_authorization_header(s.credential(tp))
    req = HttpRequest(req.method, req.url, [(n, swapped if n == "Authorization" else v) for n, v in req.headers])
    f = failure(s, req, store)
    assert f.kind == BindingFailure.WBA and f.outcome is not None and f.outcome.invalid
    # Forged credential: signed by a key the issuer does not publish.
    rogue = Setup()
    f = failure(s, request(key, url, rogue.credential(tp)), store)
    assert f.kind == BindingFailure.CREDENTIAL and f.credential is not None and not f.credential.valid
    # Unknown WBA directory: the signature is unverified.
    f = failure(s, request(key, url, s.credential(tp)), DirectoryKeyStore())
    assert f.kind == BindingFailure.WBA and f.outcome is not None and f.outcome.unverified


def test_check_binding_rejects_mismatched_inputs():
    s = Setup()
    key = wba.generate_signing_key()
    url = well_known_directory("example.com")
    req = request(key, url, s.credential(wba.thumbprint(key.public_key())))
    bound = verify(s, req, keys(url, key))
    wba.check_binding(bound.agent, req, bound.credential, s.discovery)
    # A discovery document of another entity.
    other = dict(s.discovery, entity="other.example")
    with pytest.raises(BindingFailure):
        wba.check_binding(bound.agent, req, bound.credential, other)
    # A verification result for another agent.
    from dataclasses import replace

    someone_else = replace(bound.credential, agent_id="urn:agentpin:example.com:x")
    with pytest.raises(BindingFailure):
        wba.check_binding(bound.agent, req, someone_else, s.discovery)
    with pytest.raises(BindingFailure):
        wba.check_binding(bound.agent, req, replace(bound.credential, valid=False), s.discovery)


def test_request_credential():
    req = HttpRequest("GET", "https://a.example/", [("Authorization", "AgentPin abc.def.ghi")])
    assert wba.request_credential(req) == "abc.def.ghi"
    with pytest.raises(AgentPinError):
        wba.request_credential(HttpRequest("GET", "https://a.example/"))
    with pytest.raises(AgentPinError):
        wba.request_credential(HttpRequest("GET", "https://a.example/", [("Authorization", "Bearer x")]))


def test_verify_credential_with_resolver():
    s = Setup()
    r = verify_credential_with_resolver(s.credential(), s, KeyPinStore(), None)
    assert r.valid and r.agent_id == AGENT_ID

    class Failing:
        def resolve_discovery(self, domain):
            return s.discovery

        def resolve_revocation(self, domain, discovery):
            raise OSError("down")

    r = verify_credential_with_resolver(s.credential(), Failing(), KeyPinStore(), None)
    assert not r.valid and r.error_code == "DISCOVERY_FETCH_FAILED"


@pytest.mark.parametrize(
    "web_bot_auth",
    [
        {"signature_agents": []},
        {"signature_agents": ["http://insecure.example/dir"]},
        {"signature_agents": ["https://a.example/"] * 17},
        {"signature_agents": [5]},
        {"signature_agents": "https://a.example/"},
        {},
        ["https://a.example/"],
    ],
)
def test_invalid_discovery_web_bot_auth_rejected(web_bot_auth):
    s = Setup()
    s.discovery["web_bot_auth"] = web_bot_auth
    with pytest.raises(AgentPinError):
        validate_discovery_document(s.discovery, "example.com")


def test_valid_discovery_web_bot_auth_accepted():
    Setup({"signature_agents": ["https://bots.provider.example/keys"] * 16})


def test_malformed_cnf_rejected_at_issuance():
    s = Setup()
    with pytest.raises(MalformedCredentialError):
        s.credential("not-a-thumbprint")


@pytest.mark.parametrize(
    "cnf",
    [
        {},
        {"jkt": 5},
        {"jkt": "A" * 42},
        {"jkt": "A" * 44},
        {"jkt": "A" * 42 + "B"},  # non-canonical trailing bits
        {"jkt": "A" * 42 + "="},
        "jkt",
    ],
)
def test_cnf_validation(cnf):
    payload = {
        "iss": "example.com",
        "sub": AGENT_ID,
        "jti": "j",
        "iat": 1,
        "exp": 2,
        "agentpin_version": "0.1",
        "capabilities": [],
        "cnf": cnf,
    }
    with pytest.raises(MalformedCredentialError):
        validate_claims(payload)
    payload["cnf"] = {"jkt": wba.thumbprint(wba.generate_signing_key().public_key())}
    validate_claims(payload)
    payload["cnf"] = None
    validate_claims(payload)
