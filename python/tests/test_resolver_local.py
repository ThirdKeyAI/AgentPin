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
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    assert len(store) == 1
    doc = store.resolve_discovery("example.com")
    assert doc["entity"] == "example.com"
    assert doc["agents"][0]["name"] == "Tester"


def test_register_propagates_signature_failure():
    card = _signed_card()
    card["url"] = "https://attacker.example/agent"  # tampered
    store = LocalAgentCardStore(unanchored=True)
    with pytest.raises(Exception):
        store.register(card)
    assert store.is_empty()


def test_resolve_discovery_missing_raises():
    store = LocalAgentCardStore(unanchored=True)
    with pytest.raises(Exception):
        store.resolve_discovery("missing.com")


def test_re_register_replaces_prior_entry():
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    store.register(_signed_card())
    assert len(store) == 1


def test_remove_drops_entry():
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    assert store.remove("example.com") is True
    assert store.is_empty()
    assert store.remove("example.com") is False


def test_resolve_card_returns_original():
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    card = store.resolve_card("example.com")
    assert card["name"] == "Tester"


def test_resolve_revocation_returns_none():
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    doc = store.resolve_discovery("example.com")
    assert store.resolve_revocation("example.com", doc) is None


def test_allowed_domains_propagate_into_derived_doc():
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    doc = store.resolve_discovery("example.com")
    assert doc["agents"][0]["constraints"]["allowed_domains"] == ["partner.com"]


def test_credential_verifies_through_card_derived_discovery():
    """AP-9 regression: the derived document must carry wire version "0.1".

    Before the fix it was stamped "0.3" and every credential resolved through
    the store failed with DISCOVERY_INVALID.
    """
    from agentpin import Capability, KeyPinStore, issue_credential, verify_credential_offline

    private_pem, _ = generate_key_pair()
    card = build_and_sign_agent_card(
        "https://example.com/agent",
        _declaration(),
        private_pem,
        "kid-1",
        "https://example.com/.well-known/agent-identity.json",
    )
    store = LocalAgentCardStore(unanchored=True)
    store.register(card)
    doc = store.resolve_discovery("example.com")
    assert doc["agentpin_version"] == "0.1"

    jwt_str = issue_credential(
        private_pem,
        "kid-1",
        "example.com",
        "urn:agentpin:example.com:tester",
        None,
        [Capability("read:data")],
        None,
        None,
        3600,
    )
    result = verify_credential_offline(
        jwt_str, doc, store.resolve_revocation("example.com", doc), KeyPinStore(), None
    )
    assert result.valid, result
    assert result.agent_id == "urn:agentpin:example.com:tester"


@pytest.mark.parametrize(
    "bad",
    [
        "http://example.com/.well-known/agent-identity.json",
        "https://127.0.0.1/.well-known/agent-identity.json",
        "https://example.com:8443/.well-known/agent-identity.json",
        "https://user@example.com/.well-known/agent-identity.json",
    ],
)
def test_register_rejects_non_https_or_ip_endpoint(bad):
    """AP-12: the agentpin_endpoint must be https with a domain host."""
    private_pem, _ = generate_key_pair()
    card = build_and_sign_agent_card("https://example.com/agent", _declaration(), private_pem, "kid-1", bad)
    with pytest.raises(Exception):
        LocalAgentCardStore(unanchored=True).register(card)


def test_store_normalizes_lookups():
    """AP-3: store lookups are case-insensitive."""
    store = LocalAgentCardStore(unanchored=True)
    store.register(_signed_card())
    assert store.resolve_discovery("EXAMPLE.COM.")
    assert store.resolve_card("Example.com")



def _store_trusting(card):
    from agentpin import extension_key_thumbprint

    return LocalAgentCardStore(trusted_thumbprints=[extension_key_thumbprint(card["agentpin"])])


class TestTrustAnchor:
    """AP-4 / design issue 9."""

    def test_default_store_refuses_registration(self):
        store = LocalAgentCardStore()
        with pytest.raises(Exception, match="not a trusted thumbprint"):
            store.register(_signed_card())
        assert store.is_empty()

    def test_foreign_domain_claim_is_refused(self):
        from agentpin import EntityType, build_discovery_document, card_key_published_in, pem_to_jwk

        attacker_priv, _ = generate_key_pair()
        evil = build_and_sign_agent_card(
            "https://attacker.example/agent", _declaration(), attacker_priv, "kid-1",
            "https://bank.example/.well-known/agent-identity.json",
        )
        store = _store_trusting(_signed_card())
        with pytest.raises(Exception):
            store.register(evil)
        assert store.resolve_card("bank.example") is None

        _, bank_pub = generate_key_pair()
        bank_doc = build_discovery_document(
            "bank.example", EntityType.DEPLOYER, [pem_to_jwk(bank_pub, "bank-1")], [], 0, "2026-01-15T00:00:00Z"
        )
        assert not card_key_published_in(bank_doc, evil)

        class _Resolver:
            def resolve_discovery(self, domain):
                return bank_doc

        resolver_store = LocalAgentCardStore(resolver=_Resolver())
        with pytest.raises(Exception, match="not published"):
            resolver_store.register(evil)
        assert resolver_store.is_empty()

    def test_resolver_anchor_accepts_published_key(self):
        from agentpin import EntityType, build_discovery_document, card_key_published_in, pem_to_jwk

        priv, pub = generate_key_pair()
        card = build_and_sign_agent_card(
            "https://example.com/agent", _declaration(), priv, "kid-1",
            "https://example.com/.well-known/agent-identity.json",
        )
        doc = build_discovery_document(
            "example.com", EntityType.BOTH, [pem_to_jwk(pub, "kid-1")], [], 0, "2026-01-15T00:00:00Z"
        )
        assert card_key_published_in(doc, card)

        class _Resolver:
            def resolve_discovery(self, domain):
                return doc

        store = LocalAgentCardStore(resolver=_Resolver())
        store.register(card)
        assert len(store) == 1

    def test_register_for_domain_and_trust_thumbprint(self):
        from agentpin import extension_key_thumbprint

        card = _signed_card()
        store = _store_trusting(card)
        with pytest.raises(Exception):
            store.register_for_domain(card, "other.com")
        store.register_for_domain(card, "EXAMPLE.com.")
        assert len(store) == 1
        fresh = LocalAgentCardStore()
        with pytest.raises(Exception):
            fresh.register(card)
        fresh.trust_thumbprint(extension_key_thumbprint(card["agentpin"]))
        fresh.register(card)
        with pytest.raises(Exception):
            LocalAgentCardStore(unanchored=True).trust_thumbprint("x")
