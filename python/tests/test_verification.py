"""Tests for credential verification (12-step flow)."""

from agentpin.capability import Capability
from agentpin.credential import issue_credential
from agentpin.crypto import generate_key_pair
from agentpin.discovery import build_discovery_document
from agentpin.jwk import pem_to_jwk
from agentpin.jwt import decode_jwt_unverified, encode_jwt
from agentpin.pinning import KeyPinStore
from agentpin.revocation import add_revoked_agent, add_revoked_credential, build_revocation_document
from agentpin.types import (
    AgentStatus,
    DataClassification,
    EntityType,
    ErrorCode,
    RevocationReason,
    VerifierConfig,
)
from agentpin.verification import verify_credential_offline


def setup():
    priv, pub = generate_key_pair()
    jwk = pem_to_jwk(pub, "test-2026-01")

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

    jwt_str = issue_credential(
        priv,
        "test-2026-01",
        "example.com",
        "urn:agentpin:example.com:agent",
        "verifier.com",
        [Capability("read:data"), Capability("write:report")],
        {
            "data_classification_max": DataClassification.INTERNAL,
            "rate_limit": "50/hour",
        },
        None,
        3600,
    )

    return {
        "priv": priv,
        "pub": pub,
        "jwt": jwt_str,
        "discovery": discovery,
        "revocation": build_revocation_document("example.com"),
        "pin_store": KeyPinStore(),
        "config": VerifierConfig(),
    }


class TestVerifyCredentialOffline:
    def test_happy_path(self):
        f = setup()
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert result.valid, f"Expected valid, got: {result}"
        assert result.agent_id == "urn:agentpin:example.com:agent"
        assert result.issuer == "example.com"

    def test_expired_credential(self):
        f = setup()
        header = {"alg": "ES256", "typ": "agentpin-credential+jwt", "kid": "test-2026-01"}
        payload = {
            "iss": "example.com",
            "sub": "urn:agentpin:example.com:agent",
            "iat": 1000000,
            "exp": 1003600,
            "jti": "expired-jti",
            "agentpin_version": "0.1",
            "capabilities": ["read:data"],
        }
        expired_jwt = encode_jwt(header, payload, f["priv"])
        result = verify_credential_offline(
            expired_jwt, f["discovery"], None, KeyPinStore(), None, f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CREDENTIAL_EXPIRED

    def test_wrong_algorithm_rejected(self):
        f = setup()
        result = verify_credential_offline(
            "invalid.jwt.token", f["discovery"], None, KeyPinStore(), None, f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.ALGORITHM_REJECTED

    def test_credential_revoked(self):
        f = setup()
        _, payload, _ = decode_jwt_unverified(f["jwt"])
        add_revoked_credential(f["revocation"], payload["jti"], RevocationReason.KEY_COMPROMISE)
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CREDENTIAL_REVOKED

    def test_agent_revoked(self):
        f = setup()
        add_revoked_agent(
            f["revocation"], "urn:agentpin:example.com:agent", RevocationReason.PRIVILEGE_WITHDRAWN
        )
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid

    def test_inactive_agent(self):
        f = setup()
        f["discovery"]["agents"][0]["status"] = AgentStatus.SUSPENDED
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.AGENT_INACTIVE

    def test_capability_exceeded(self):
        f = setup()
        f["discovery"]["agents"][0]["capabilities"] = ["read:limited"]
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CAPABILITY_EXCEEDED

    def test_audience_mismatch(self):
        f = setup()
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "wrong-verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.AUDIENCE_MISMATCH

    def test_key_pin_change_rejected(self):
        f = setup()
        # First verification pins
        result1 = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert result1.valid

        # Change key
        priv2, pub2 = generate_key_pair()
        jwk2 = pem_to_jwk(pub2, "test-2026-01")
        f["discovery"]["public_keys"] = [jwk2]

        jwt2 = issue_credential(
            priv2, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 3600,
        )

        result2 = verify_credential_offline(
            jwt2, f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result2.valid
        assert result2.error_code == ErrorCode.KEY_PIN_MISMATCH

    def test_domain_mismatch(self):
        f = setup()
        f["discovery"]["entity"] = "other.com"
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], None, f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.DISCOVERY_INVALID

    def test_wildcard_audience_accepted(self):
        priv, pub = generate_key_pair()
        jwk = pem_to_jwk(pub, "test-key")

        discovery = build_discovery_document(
            "example.com",
            EntityType.MAKER,
            [jwk],
            [
                {
                    "agent_id": "urn:agentpin:example.com:agent",
                    "name": "Test",
                    "capabilities": ["read:*"],
                    "status": AgentStatus.ACTIVE,
                }
            ],
            2,
            "2026-01-15T00:00:00Z",
        )

        jwt_str = issue_credential(
            priv, "test-key", "example.com", "urn:agentpin:example.com:agent",
            "*", [Capability("read:data")], None, None, 3600,
        )

        result = verify_credential_offline(
            jwt_str, discovery, None, KeyPinStore(), "any-verifier.com", VerifierConfig()
        )
        assert result.valid, "Wildcard audience should be accepted"
