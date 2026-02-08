"""Tests for credential issuance and validation."""

import pytest

from agentpin.capability import Capability
from agentpin.credential import issue_credential, validate_credential_against_discovery
from agentpin.crypto import generate_key_pair
from agentpin.jwt import verify_jwt
from agentpin.types import AgentPinError


class TestIssueCredential:
    def test_issues_and_verifies(self):
        priv, pub = generate_key_pair()
        jwt_str = issue_credential(
            priv,
            "test-2026-01",
            "example.com",
            "urn:agentpin:example.com:agent",
            "verifier.com",
            [Capability("read:data")],
            None,
            None,
            3600,
        )
        header, payload = verify_jwt(jwt_str, pub)
        assert header["kid"] == "test-2026-01"
        assert payload["iss"] == "example.com"
        assert payload["sub"] == "urn:agentpin:example.com:agent"
        assert payload["aud"] == "verifier.com"
        assert payload["agentpin_version"] == "0.1"
        assert payload["exp"] > payload["iat"]


class TestValidateCredentialAgainstDiscovery:
    def test_valid_subset(self):
        validate_credential_against_discovery(["read:data"], ["read:*", "write:report"])

    def test_exceeding_raises(self):
        with pytest.raises(AgentPinError, match="exceed"):
            validate_credential_against_discovery(["delete:data"], ["read:data"])
