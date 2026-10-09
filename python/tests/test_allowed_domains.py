"""Tests for AllowedDomains helpers + a2a_endpoint discovery field (v0.3.0)."""

import pytest

from agentpin import (
    AllowedDomains,
    EntityType,
    build_discovery_document,
)


def test_unrestricted_accepts_anything():
    ad = AllowedDomains.unrestricted()
    assert AllowedDomains.is_unrestricted(ad)
    assert AllowedDomains.allows(ad, "anything.com")


def test_restricted_filters():
    ad = AllowedDomains.from_domains(["a.com", "b.com"])
    assert not AllowedDomains.is_unrestricted(ad)
    assert AllowedDomains.allows(ad, "a.com")
    assert not AllowedDomains.allows(ad, "c.com")


def test_intersect_with_unrestricted_returns_other():
    unrestricted = AllowedDomains.unrestricted()
    restricted = AllowedDomains.from_domains(["a.com", "b.com"])
    assert AllowedDomains.intersect(unrestricted, restricted) == restricted
    assert AllowedDomains.intersect(restricted, unrestricted) == restricted


def test_intersect_returns_overlap():
    lhs = AllowedDomains.from_domains(["a.com", "b.com", "c.com"])
    rhs = AllowedDomains.from_domains(["b.com", "c.com", "d.com"])
    assert AllowedDomains.intersect(lhs, rhs) == ["b.com", "c.com"]


def test_from_constraints_with_list():
    out = AllowedDomains.from_constraints({"allowed_domains": ["a.com"]})
    assert out == ["a.com"]


def test_from_constraints_without_field():
    assert AllowedDomains.is_unrestricted(AllowedDomains.from_constraints({}))
    assert AllowedDomains.is_unrestricted(AllowedDomains.from_constraints(None))


def test_build_discovery_document_with_a2a_endpoint():
    doc = build_discovery_document(
        "example.com",
        EntityType.MAKER,
        [{"kid": "k", "kty": "EC", "crv": "P-256", "x": "x", "y": "y"}],
        [],
        2,
        "2026-05-01T00:00:00Z",
        a2a_endpoint="https://example.com/.well-known/agent-card.json",
    )
    assert doc["a2a_endpoint"] == "https://example.com/.well-known/agent-card.json"


def test_build_discovery_document_without_a2a_endpoint_omits_field():
    doc = build_discovery_document(
        "example.com",
        EntityType.MAKER,
        [{"kid": "k", "kty": "EC", "crv": "P-256", "x": "x", "y": "y"}],
        [],
        2,
        "2026-05-01T00:00:00Z",
    )
    assert "a2a_endpoint" not in doc


def test_from_constraints_empty_list_is_restricted():
    """AP-6: a present-but-empty list is restricted to nothing."""
    assert not AllowedDomains.is_unrestricted(AllowedDomains.from_constraints({"allowed_domains": []}))


def test_intersect_of_disjoint_lists_allows_nothing():
    """AP-6: disjoint allow-lists intersect to "restricted to nothing"."""
    inter = AllowedDomains.intersect(["a.com"], ["b.com"])
    assert inter == []
    assert not AllowedDomains.is_unrestricted(inter)
    assert not AllowedDomains.allows(inter, "a.com")
    assert not AllowedDomains.allows(inter, "anything.com")
    assert not AllowedDomains.allows([], "x.com")


def test_pattern_matching():
    """AP-6: allows and intersect use the §5.5 pattern rules."""
    assert AllowedDomains.allows(["*.corp.com"], "api.corp.com")
    assert not AllowedDomains.allows(["*.corp.com"], "corp.com")
    assert not AllowedDomains.allows(["*.corp.com"], "evil-corp.com")
    assert AllowedDomains.intersect(["*.corp.com"], ["api.corp.com"]) == ["api.corp.com"]
    assert AllowedDomains.intersect(["api.corp.com"], ["*.corp.com"]) == ["api.corp.com"]
