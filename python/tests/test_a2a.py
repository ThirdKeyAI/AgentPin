"""Tests for A2A AgentCard types, builder, and verification (v0.3.0)."""

import json

import pytest

from agentpin import (
    AgentStatus,
    build_and_sign_agent_card,
    build_unsigned_agent_card,
    canonicalize_for_signing,
    capability_to_skill,
    extension_key_thumbprint,
    generate_key_pair,
    jwk_thumbprint,
    sign_agent_card,
    verify_agentpin_extension,
)


def _declaration(capabilities, allowed_domains=None):
    decl = {
        "agent_id": "urn:agentpin:example.com:test",
        "name": "Test Agent",
        "description": "test",
        "version": "1.0.0",
        "capabilities": capabilities,
        "credential_ttl_max": 3600,
        "status": AgentStatus.ACTIVE,
    }
    if allowed_domains is not None:
        decl["constraints"] = {"allowed_domains": allowed_domains}
    return decl


def test_capability_to_skill_maps_string():
    skill = capability_to_skill("read:customers/*")
    assert skill["id"] == "read:customers/*"
    assert skill["name"] == "read:customers/*"


def test_build_unsigned_card_maps_capabilities_to_skills():
    card = build_unsigned_agent_card(
        "https://example.com/agent",
        _declaration(["read:customers", "write:invoices"]),
    )
    assert len(card["skills"]) == 2
    assert card["skills"][0]["id"] == "read:customers"
    assert "agentpin" not in card


def test_build_unsigned_card_maps_allowed_domains():
    card = build_unsigned_agent_card(
        "https://example.com/agent",
        _declaration(["read:*"], ["a.com", "b.com"]),
    )
    assert card["capabilities"]["allowed_domains"] == ["a.com", "b.com"]


def test_build_unsigned_card_omits_allowed_domains_when_unrestricted():
    card = build_unsigned_agent_card(
        "https://example.com/agent", _declaration(["read:*"])
    )
    assert "allowed_domains" not in card["capabilities"]


def test_sign_requires_agentpin_endpoint():
    private_pem, _ = generate_key_pair()
    unsigned = build_unsigned_agent_card(
        "https://example.com/agent", _declaration(["read:*"])
    )
    with pytest.raises(Exception):
        sign_agent_card(unsigned, private_pem, "kid-1", "")


def test_signed_card_round_trips_and_verifies():
    private_pem, _ = generate_key_pair()
    card = build_and_sign_agent_card(
        "https://example.com/agent",
        _declaration(["read:customers", "write:invoices"], ["partner.com"]),
        private_pem,
        "kid-1",
        "https://example.com/.well-known/agent-identity.json",
        streaming=True,
    )
    assert "agentpin" in card
    verify_agentpin_extension(card)
    parsed = json.loads(json.dumps(card))
    verify_agentpin_extension(parsed)


def test_verify_fails_when_extension_missing():
    card = build_unsigned_agent_card(
        "https://example.com/agent", _declaration(["read:*"])
    )
    with pytest.raises(Exception, match="no agentpin extension"):
        verify_agentpin_extension(card)


def test_verify_fails_when_card_tampered():
    private_pem, _ = generate_key_pair()
    card = build_and_sign_agent_card(
        "https://example.com/agent",
        _declaration(["read:customers"]),
        private_pem,
        "kid-1",
        "https://example.com/.well-known/agent-identity.json",
    )
    card["url"] = "https://attacker.example/agent"
    with pytest.raises(Exception, match="did not verify"):
        verify_agentpin_extension(card)


def test_extension_key_thumbprint_matches_jwk_thumbprint():
    private_pem, _ = generate_key_pair()
    card = build_and_sign_agent_card(
        "https://example.com/agent",
        _declaration(["read:*"]),
        private_pem,
        "kid-1",
        "https://example.com/.well-known/agent-identity.json",
    )
    ext = card["agentpin"]
    assert extension_key_thumbprint(ext) == jwk_thumbprint(ext["public_key_jwk"])


def test_canonicalize_sorts_keys_and_drops_none():
    out = canonicalize_for_signing({"b": 1, "a": {"d": 4, "c": 3}, "z": None})
    assert out == '{"a":{"c":3,"d":4},"b":1}'


def test_canonicalize_recurses_into_arrays():
    out = canonicalize_for_signing([{"b": 1, "a": 2}])
    assert out == '[{"a":2,"b":1}]'
