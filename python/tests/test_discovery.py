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
