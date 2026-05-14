"""Tests for A2aAgentCardResolver (v0.3.0).

Uses a stub fetch so we don't need a real HTTP server.
"""

import pytest

from agentpin import (
    A2aAgentCardResolver,
    AgentStatus,
    build_and_sign_agent_card,
    generate_key_pair,
)


def _signed_card_for(domain):
    private_pem, _ = generate_key_pair()
    decl = {
        "agent_id": f"urn:agentpin:{domain}:test",
        "name": "Test Agent",
        "description": "desc",
        "version": "1.0.0",
        "capabilities": ["read:*"],
        "credential_ttl_max": 3600,
        "status": AgentStatus.ACTIVE,
    }
    return build_and_sign_agent_card(
        f"https://{domain}/agent",
        decl,
        private_pem,
        "kid-1",
        f"https://{domain}/.well-known/agent-identity.json",
    )


class _StubResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.ok = 200 <= status_code < 300
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


def _stub_fetch(routes):
    def fetch(url):
        entry = routes.get(url)
        if entry is None:
            raise AssertionError(f"unexpected fetch: {url}")
        return entry
    return fetch


def test_resolves_and_verifies_a_card():
    card = _signed_card_for("example.com")
    fetch = _stub_fetch({
        "https://example.com/.well-known/agent-card.json": _StubResponse(200, card),
    })
    resolver = A2aAgentCardResolver(fetch=fetch)
    doc = resolver.resolve_discovery("example.com")
    assert doc["entity"] == "example.com"
    assert len(doc["public_keys"]) == 1
    assert resolver.last_card("example.com") == card


def test_rejects_http_error_response():
    fetch = _stub_fetch({
        "https://example.com/.well-known/agent-card.json": _StubResponse(404),
    })
    resolver = A2aAgentCardResolver(fetch=fetch)
    with pytest.raises(Exception, match="HTTP 404"):
        resolver.resolve_discovery("example.com")


def test_rejects_card_whose_extension_does_not_verify():
    card = _signed_card_for("example.com")
    card["url"] = "https://attacker.example/agent"  # tamper
    fetch = _stub_fetch({
        "https://example.com/.well-known/agent-card.json": _StubResponse(200, card),
    })
    resolver = A2aAgentCardResolver(fetch=fetch)
    with pytest.raises(Exception, match="did not verify"):
        resolver.resolve_discovery("example.com")


def test_rejects_endpoint_host_mismatch():
    card = _signed_card_for("other.com")  # valid for other.com
    fetch = _stub_fetch({
        "https://example.com/.well-known/agent-card.json": _StubResponse(200, card),
    })
    resolver = A2aAgentCardResolver(fetch=fetch)
    with pytest.raises(Exception, match="mismatch"):
        resolver.resolve_discovery("example.com")


def test_resolve_revocation_returns_none():
    card = _signed_card_for("example.com")
    fetch = _stub_fetch({
        "https://example.com/.well-known/agent-card.json": _StubResponse(200, card),
    })
    resolver = A2aAgentCardResolver(fetch=fetch)
    doc = resolver.resolve_discovery("example.com")
    assert resolver.resolve_revocation("example.com", doc) is None
