"""Tests for trust bundle support."""

import json
import tempfile
import os

from agentpin.bundle import (
    create_trust_bundle,
    find_bundle_discovery,
    find_bundle_revocation,
    load_trust_bundle,
    save_trust_bundle,
    verify_credential_with_bundle,
)
from agentpin.capability import Capability
from agentpin.credential import issue_credential
from agentpin.crypto import generate_key_pair, generate_key_id
from agentpin.discovery import build_discovery_document
from agentpin.jwk import pem_to_jwk
from agentpin.jwt import decode_jwt_unverified
from agentpin.pinning import KeyPinStore
from agentpin.revocation import build_revocation_document, add_revoked_credential
from agentpin.types import (
    AgentStatus,
    DataClassification,
    EntityType,
    ErrorCode,
    RevocationReason,
)


def _setup():
    private_pem, public_pem = generate_key_pair()
    kid = generate_key_id(public_pem)
    jwk = pem_to_jwk(public_pem, kid)

    discovery = build_discovery_document(
        "example.com",
        EntityType.MAKER,
        [jwk],
        [
            {
                "agent_id": "urn:agentpin:example.com:agent",
                "name": "Test Agent",
                "capabilities": ["read:*", "write:report"],
                "constraints": {
                    "data_classification_max": DataClassification.CONFIDENTIAL,
                    "rate_limit": "100/hour",
                },
                "status": AgentStatus.ACTIVE,
            }
        ],
        2,
        "2026-01-15T00:00:00Z",
    )

    revocation = build_revocation_document("example.com")

    jwt_token = issue_credential(
        private_pem,
        kid,
        "example.com",
        "urn:agentpin:example.com:agent",
        "verifier.com",
        [Capability("read:data"), Capability("write:report")],
        {"data_classification_max": DataClassification.INTERNAL, "rate_limit": "50/hour"},
        None,  # no delegation chain
        3600,
    )

    return {
        "private_pem": private_pem,
        "public_pem": public_pem,
        "kid": kid,
        "jwk": jwk,
        "discovery": discovery,
        "revocation": revocation,
        "jwt": jwt_token,
    }


class TestTrustBundle:
    def test_create_trust_bundle(self):
        bundle = create_trust_bundle("2026-02-10T00:00:00Z")
        assert bundle["agentpin_bundle_version"] == "0.1"
        assert bundle["created_at"] == "2026-02-10T00:00:00Z"
        assert bundle["documents"] == []
        assert bundle["revocations"] == []

    def test_find_bundle_discovery(self):
        f = _setup()
        bundle = create_trust_bundle()
        bundle["documents"].append(f["discovery"])

        doc = find_bundle_discovery(bundle, "example.com")
        assert doc is not None
        assert doc["entity"] == "example.com"

    def test_find_bundle_discovery_missing(self):
        bundle = create_trust_bundle()
        assert find_bundle_discovery(bundle, "missing.com") is None

    def test_find_bundle_revocation(self):
        f = _setup()
        bundle = create_trust_bundle()
        bundle["revocations"].append(f["revocation"])

        doc = find_bundle_revocation(bundle, "example.com")
        assert doc is not None
        assert doc["entity"] == "example.com"

    def test_find_bundle_revocation_missing(self):
        bundle = create_trust_bundle()
        assert find_bundle_revocation(bundle, "example.com") is None

    def test_json_roundtrip(self):
        f = _setup()
        bundle = create_trust_bundle("2026-02-10T00:00:00Z")
        bundle["documents"].append(f["discovery"])

        json_str = json.dumps(bundle)
        parsed = json.loads(json_str)

        assert parsed["agentpin_bundle_version"] == "0.1"
        assert len(parsed["documents"]) == 1
        assert parsed["documents"][0]["entity"] == "example.com"

    def test_save_and_load_bundle(self):
        f = _setup()
        bundle = create_trust_bundle("2026-02-10T00:00:00Z")
        bundle["documents"].append(f["discovery"])

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            save_trust_bundle(bundle, tmp_path)
            loaded = load_trust_bundle(tmp_path)
            assert loaded["agentpin_bundle_version"] == "0.1"
            assert len(loaded["documents"]) == 1
        finally:
            os.unlink(tmp_path)


class TestVerifyCredentialWithBundle:
    def test_valid_credential(self):
        f = _setup()
        bundle = create_trust_bundle()
        bundle["documents"].append(f["discovery"])
        bundle["revocations"].append(f["revocation"])

        pin_store = KeyPinStore()
        result = verify_credential_with_bundle(f["jwt"], bundle, pin_store, "verifier.com")

        assert result.valid is True
        assert result.agent_id == "urn:agentpin:example.com:agent"
        assert result.issuer == "example.com"

    def test_domain_not_in_bundle(self):
        f = _setup()
        bundle = create_trust_bundle()  # empty

        pin_store = KeyPinStore()
        result = verify_credential_with_bundle(f["jwt"], bundle, pin_store, "verifier.com")

        assert result.valid is False
        assert result.error_code == ErrorCode.DISCOVERY_FETCH_FAILED
        assert "not found in trust bundle" in result.error_message

    def test_revoked_credential_detected(self):
        f = _setup()
        bundle = create_trust_bundle()
        bundle["documents"].append(f["discovery"])

        # Revoke the credential
        _header, payload, _sig = decode_jwt_unverified(f["jwt"])
        rev_doc = build_revocation_document("example.com")
        add_revoked_credential(rev_doc, payload["jti"], RevocationReason.KEY_COMPROMISE)
        bundle["revocations"].append(rev_doc)

        pin_store = KeyPinStore()
        result = verify_credential_with_bundle(f["jwt"], bundle, pin_store, "verifier.com")

        assert result.valid is False
        assert result.error_code == ErrorCode.CREDENTIAL_REVOKED
