"""Cross-SDK conformance vectors shared with the Rust, Go and JavaScript
suites (testdata/conformance/vectors.json at the repository root)."""

import copy
import json
from pathlib import Path

import pytest

from agentpin.a2a import verify_agentpin_extension
from agentpin.capability import Capability
from agentpin.credential import issue_credential
from agentpin.crypto import domain_separated_input, generate_key_pair
from agentpin.discovery import validate_discovery_document
from agentpin.jwk import pem_to_jwk
from agentpin.pinning import KeyPinStore
from agentpin.types import AgentPinError
from agentpin.verification import verify_credential_offline

DIR = Path(__file__).resolve().parents[2] / "testdata" / "conformance"
VECTORS = json.loads((DIR / "vectors.json").read_text())
AGENT = "urn:agentpin:example.com:test-agent"


def discovery():
    return json.loads((DIR / "discovery.json").read_text())


@pytest.mark.parametrize("case", VECTORS["credentials"], ids=lambda c: c["name"])
def test_malformed_credentials_rejected(case):
    r = verify_credential_offline(case["jwt"], discovery(), None, KeyPinStore(), None)
    assert not r.valid
    assert r.error_code == case["error_code"]


def test_case_variant_issuer_hits_existing_pin():
    v = VECTORS["case_variant_issuer"]
    d = discovery()
    store = KeyPinStore()
    store.check_and_pin("example.com", d["public_keys"][0])
    priv, pub = generate_key_pair()
    evil = dict(d, entity=v["issuer"], public_keys=[pem_to_jwk(pub, "evil-key")])
    jwt = issue_credential(priv, "evil-key", v["issuer"], AGENT, None, [Capability("read:data")], None, None, 3600)
    r = verify_credential_offline(jwt, evil, None, store, None)
    assert not r.valid
    assert r.error_code == v["error_code"]


def test_revocation_wrong_field_names_rejected():
    v = VECTORS["revocation_wrong_field_names"]
    priv = (DIR / "example-2026-01.private.pem").read_text()
    jwt = issue_credential(priv, "example-2026-01", "example.com", AGENT, None,
                           [Capability("read:data")], None, None, 3600)
    r = verify_credential_offline(jwt, discovery(), copy.deepcopy(v["document"]), KeyPinStore(), None)
    assert not r.valid
    assert r.error_code == v["error_code"]


@pytest.mark.parametrize("url", VECTORS["invalid_revocation_endpoints"])
def test_invalid_revocation_endpoint_rejected(url):
    d = dict(discovery(), revocation_endpoint=url)
    with pytest.raises(AgentPinError):
        validate_discovery_document(d, "example.com")


@pytest.mark.parametrize("case", VECTORS["agent_cards"], ids=lambda c: c["name"])
def test_agent_cards(case):
    try:
        verify_agentpin_extension(copy.deepcopy(case["card"]))
        ok = True
    except AgentPinError:
        ok = False
    assert ok == case["valid"]


def test_domain_separated_input_layout():
    v = VECTORS["domain_separated_input"]
    fields = [bytes.fromhex(h) for h in v["fields_hex"]]
    assert domain_separated_input(v["context"], fields).hex() == v["expected_hex"]
