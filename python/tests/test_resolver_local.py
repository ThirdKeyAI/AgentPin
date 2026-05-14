"""Tests for LocalAgentCardStore (v0.3.0)."""

import pytest

from agentpin import (
    AgentStatus,
    LocalAgentCardStore,
    build_and_sign_agent_card,
    card_endpoint_host,
    derive_discovery_from_card,
    generate_key_pair,
)


def _declaration():
    return {
        "agent_id": "urn:agentpin:example.com:tester",
        "name": "Tester",
        "description": "Test agent",
        "version": "1.0.0",
        "capabilities": ["read:*"],
        "constraints": {"allowed_domains": ["partner.com"]},
        "credential_ttl_max": 3600,
        "status": AgentStatus.ACTIVE,
    }


def _signed_card():
    private_pem, _ = generate_key_pair()
    return build_and_sign_agent_card(
        "https://example.com/agent",
        _declaration(),
        private_pem,
        "kid-1",
        "https://example.com/.well-known/agent-identity.json",
    )


def test_card_endpoint_host():
    card = _signed_card()
    assert card_endpoint_host(card) == "example.com"


def test_card_endpoint_host_without_extension_raises():
    with pytest.raises(Exception):
        card_endpoint_host({"name": "x"})


def test_derive_discovery_from_card():
    card = _signed_card()
    doc = derive_discovery_from_card(card)
    assert doc["entity"] == "example.com"
    assert len(doc["public_keys"]) == 1
    assert len(doc["agents"]) == 1
    assert doc["agents"][0]["name"] == "Tester"
    assert doc["agents"][0]["capabilities"] == ["read:*"]
    assert doc["agents"][0]["constraints"]["allowed_domains"] == ["partner.com"]
    assert doc["a2a_endpoint"] == "https://example.com/.well-known/agent-identity.json"


def test_register_then_resolve():
    store = LocalAgentCardStore()
    store.register(_signed_card())
    assert len(store) == 1
    doc = store.resolve_discovery("example.com")
    assert doc["entity"] == "example.com"
    assert doc["agents"][0]["name"] == "Tester"


def test_register_propagates_signature_failure():
    card = _signed_card()
    card["url"] = "https://attacker.example/agent"  # tampered
    store = LocalAgentCardStore()
    with pytest.raises(Exception):
        store.register(card)
    assert store.is_empty()


def test_resolve_discovery_missing_raises():
    store = LocalAgentCardStore()
    with pytest.raises(Exception):
        store.resolve_discovery("missing.com")


def test_re_register_replaces_prior_entry():
    store = LocalAgentCardStore()
    store.register(_signed_card())
    store.register(_signed_card())
    assert len(store) == 1


def test_remove_drops_entry():
    store = LocalAgentCardStore()
    store.register(_signed_card())
    assert store.remove("example.com") is True
    assert store.is_empty()
    assert store.remove("example.com") is False


def test_resolve_card_returns_original():
    store = LocalAgentCardStore()
    store.register(_signed_card())
    card = store.resolve_card("example.com")
    assert card["name"] == "Tester"


def test_resolve_revocation_returns_none():
    store = LocalAgentCardStore()
    store.register(_signed_card())
    doc = store.resolve_discovery("example.com")
    assert store.resolve_revocation("example.com", doc) is None


def test_allowed_domains_propagate_into_derived_doc():
    store = LocalAgentCardStore()
    store.register(_signed_card())
    doc = store.resolve_discovery("example.com")
    assert doc["agents"][0]["constraints"]["allowed_domains"] == ["partner.com"]
