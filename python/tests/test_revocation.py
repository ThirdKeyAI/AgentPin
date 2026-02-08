"""Tests for revocation document handling."""

import pytest

from agentpin.revocation import (
    add_revoked_agent,
    add_revoked_credential,
    add_revoked_key,
    build_revocation_document,
    check_revocation,
)
from agentpin.types import AgentPinError, RevocationReason


class TestBuildRevocationDocument:
    def test_creates_empty(self):
        doc = build_revocation_document("example.com")
        assert doc["entity"] == "example.com"
        assert len(doc["revoked_credentials"]) == 0
        assert len(doc["revoked_agents"]) == 0
        assert len(doc["revoked_keys"]) == 0


class TestAddRevocations:
    def test_adds_and_counts(self):
        doc = build_revocation_document("example.com")
        add_revoked_credential(doc, "jti-123", RevocationReason.KEY_COMPROMISE)
        add_revoked_agent(doc, "urn:agentpin:example.com:bad-agent", RevocationReason.POLICY_VIOLATION)
        add_revoked_key(doc, "old-key-01", RevocationReason.SUPERSEDED)

        assert len(doc["revoked_credentials"]) == 1
        assert len(doc["revoked_agents"]) == 1
        assert len(doc["revoked_keys"]) == 1


class TestCheckRevocation:
    def test_clean_passes(self):
        doc = build_revocation_document("example.com")
        check_revocation(doc, "jti-1", "agent-1", "key-1")

    def test_credential_revoked(self):
        doc = build_revocation_document("example.com")
        add_revoked_credential(doc, "jti-bad", RevocationReason.KEY_COMPROMISE)
        with pytest.raises(AgentPinError, match="jti-bad"):
            check_revocation(doc, "jti-bad", "agent-1", "key-1")
        check_revocation(doc, "jti-good", "agent-1", "key-1")  # should not raise

    def test_agent_revoked(self):
        doc = build_revocation_document("example.com")
        add_revoked_agent(doc, "bad-agent", RevocationReason.PRIVILEGE_WITHDRAWN)
        with pytest.raises(AgentPinError, match="bad-agent"):
            check_revocation(doc, "jti-1", "bad-agent", "key-1")

    def test_key_revoked(self):
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "bad-key", RevocationReason.SUPERSEDED)
        with pytest.raises(AgentPinError, match="bad-key"):
            check_revocation(doc, "jti-1", "agent-1", "bad-key")
