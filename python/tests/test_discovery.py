"""Tests for discovery document handling."""

import pytest

from agentpin.discovery import (
    build_discovery_document,
    find_agent_by_id,
    find_key_by_kid,
    validate_discovery_document,
)
from agentpin.types import AgentPinError, AgentStatus, EntityType


def make_test_doc():
    return build_discovery_document(
        "example.com",
        EntityType.MAKER,
        [
            {
                "kid": "example-2026-01",
                "kty": "EC",
                "crv": "P-256",
                "x": "test-x",
                "y": "test-y",
                "use": "sig",
                "key_ops": ["verify"],
            }
        ],
        [
            {
                "agent_id": "urn:agentpin:example.com:agent",
                "name": "Test Agent",
                "capabilities": ["read:*"],
                "status": AgentStatus.ACTIVE,
            }
        ],
        2,
        "2026-01-15T00:00:00Z",
    )


class TestValidateDiscoveryDocument:
    def test_valid(self):
        doc = make_test_doc()
        validate_discovery_document(doc, "example.com")

    def test_domain_mismatch(self):
        doc = make_test_doc()
        with pytest.raises(AgentPinError, match="does not match"):
            validate_discovery_document(doc, "other.com")


class TestFindKeyByKid:
    def test_found(self):
        doc = make_test_doc()
        assert find_key_by_kid(doc, "example-2026-01") is not None

    def test_not_found(self):
        doc = make_test_doc()
        assert find_key_by_kid(doc, "nonexistent") is None


class TestFindAgentById:
    def test_found(self):
        doc = make_test_doc()
        assert find_agent_by_id(doc, "urn:agentpin:example.com:agent") is not None

    def test_not_found(self):
        doc = make_test_doc()
        assert find_agent_by_id(doc, "urn:agentpin:example.com:other") is None


def _base_doc():
    return {
        "agentpin_version": "0.1",
        "entity": "example.com",
        "entity_type": "maker",
        "public_keys": [{"kid": "k", "kty": "EC", "crv": "P-256", "x": "x", "y": "y", "use": "sig"}],
        "agents": [],
        "max_delegation_depth": 2,
        "updated_at": "2026-01-15T00:00:00Z",
    }


def test_validate_entity_normalized():
    """AP-3: entity comparison is case-insensitive and ignores a trailing dot."""
    doc = dict(_base_doc(), entity="EXAMPLE.com.")
    validate_discovery_document(doc, "example.com")
    validate_discovery_document(doc, "Example.COM")


@pytest.mark.parametrize(
    "bad",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/latest/meta-data/",
        "https://other.com/.well-known/agent-identity-revocations.json",
        "http://example.com/.well-known/agent-identity-revocations.json",
        "https://example.com:8443/revocations.json",
        "https://user@example.com/revocations.json",
    ],
)
def test_validate_rejects_foreign_or_plaintext_endpoints(bad):
    """AP-12: revocation_endpoint / a2a_endpoint must be https on the entity's own host."""
    with pytest.raises(AgentPinError):
        validate_discovery_document(dict(_base_doc(), revocation_endpoint=bad), "example.com")
    with pytest.raises(AgentPinError):
        validate_discovery_document(dict(_base_doc(), a2a_endpoint=bad), "example.com")


def test_validate_accepts_same_host_a2a_endpoint():
    validate_discovery_document(
        dict(_base_doc(), a2a_endpoint="https://EXAMPLE.com/.well-known/agent-card.json"), "example.com"
    )
