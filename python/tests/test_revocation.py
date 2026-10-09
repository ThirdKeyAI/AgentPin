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


class TestSignedRevocationDocument:
    """Design issue 3."""

    def test_sign_verify_tamper_and_entity_binding(self):
        from datetime import datetime, timedelta, timezone

        from agentpin import build_discovery_document, generate_key_pair, pem_to_jwk
        from agentpin.revocation import (
            add_revoked_key,
            build_revocation_document,
            check_revocation_freshness,
            sign_revocation_document,
            verify_revocation_document,
        )
        from agentpin.types import AgentPinError

        priv, pub = generate_key_pair()
        discovery = build_discovery_document(
            "example.com", "maker", [pem_to_jwk(pub, "k1")], [], 2, "2026-01-15T00:00:00Z"
        )
        doc = build_revocation_document("example.com")
        add_revoked_key(doc, "old", "superseded")
        verify_revocation_document(doc, discovery)
        sign_revocation_document(doc, priv, "k1")
        verify_revocation_document(doc, discovery)
        import json

        verify_revocation_document(json.loads(json.dumps(doc)), discovery)
        with pytest.raises(AgentPinError, match="did not verify"):
            verify_revocation_document(dict(doc, revoked_keys=[]), discovery)
        with pytest.raises(AgentPinError, match="not found"):
            verify_revocation_document(dict(doc, kid="other"), discovery)
        with pytest.raises(AgentPinError, match="does not match"):
            verify_revocation_document(build_revocation_document("other.com"), discovery)
        verify_revocation_document(build_revocation_document("EXAMPLE.com."), discovery)

        fresh = build_revocation_document("example.com")
        check_revocation_freshness(fresh, 3600)
        stale = dict(fresh, updated_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat())
        with pytest.raises(AgentPinError, match="stale"):
            check_revocation_freshness(stale, 3600)
        with pytest.raises(AgentPinError, match="RFC 3339"):
            check_revocation_freshness(dict(fresh, updated_at="yesterday"), 3600)
