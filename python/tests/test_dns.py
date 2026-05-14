"""Tests for DNS TXT cross-verification (v0.3.0)."""

import pytest

from agentpin import (
    EntityType,
    generate_key_pair,
    jwk_thumbprint,
    parse_txt_record,
    pem_to_jwk,
    txt_record_name,
    verify_dns_match,
)


def _discovery(jwks):
    return {
        "agentpin_version": "0.3",
        "entity": "example.com",
        "entity_type": EntityType.MAKER,
        "public_keys": jwks,
        "agents": [],
        "max_delegation_depth": 0,
        "updated_at": "2026-05-01T00:00:00Z",
    }


def test_parse_full_record():
    r = parse_txt_record("v=agentpin1; kid=acme-2026-04; fp=sha256:abcd1234")
    assert r["version"] == "agentpin1"
    assert r["kid"] == "acme-2026-04"
    assert r["fingerprint"] == "sha256:abcd1234"


def test_parse_minimal_record():
    r = parse_txt_record("v=agentpin1;fp=sha256:abc")
    assert r["version"] == "agentpin1"
    assert r["kid"] is None
    assert r["fingerprint"] == "sha256:abc"


def test_parse_lowercases_fingerprint():
    r = parse_txt_record("v=agentpin1; fp=SHA256:ABCDEF")
    assert r["fingerprint"] == "sha256:abcdef"


def test_parse_tolerates_whitespace_and_order():
    r = parse_txt_record("  fp = sha256:beef ;  v = agentpin1  ")
    assert r["version"] == "agentpin1"
    assert r["fingerprint"] == "sha256:beef"


def test_parse_ignores_unknown_fields():
    r = parse_txt_record("v=agentpin1; fp=sha256:abc; future=ignoreme")
    assert r["fingerprint"] == "sha256:abc"


def test_parse_missing_v_fails():
    with pytest.raises(Exception):
        parse_txt_record("fp=sha256:abc")


def test_parse_missing_fp_fails():
    with pytest.raises(Exception):
        parse_txt_record("v=agentpin1")


def test_parse_unsupported_version_fails():
    with pytest.raises(Exception):
        parse_txt_record("v=agentpin99; fp=sha256:abc")


def test_parse_fp_without_sha256_prefix_fails():
    with pytest.raises(Exception):
        parse_txt_record("v=agentpin1; fp=abc")


def test_parse_field_without_equals_fails():
    with pytest.raises(Exception):
        parse_txt_record("v=agentpin1; broken")


def test_schemapin_record_rejected():
    """Sanity: must reject SchemaPin's TXT format."""
    with pytest.raises(Exception):
        parse_txt_record("v=schemapin1; fp=sha256:abc")


def _fp_for(jwk):
    t = jwk_thumbprint(jwk).lower()
    return t if t.startswith("sha256:") else f"sha256:{t}"


def test_verify_match_against_single_key():
    _, public_pem = generate_key_pair()
    jwk = pem_to_jwk(public_pem, "kid-1")
    doc = _discovery([jwk])
    txt = {"kid": None, "fingerprint": _fp_for(jwk)}
    verify_dns_match(doc, txt)


def test_verify_match_against_one_of_multiple_keys():
    _, pk1 = generate_key_pair()
    _, pk2 = generate_key_pair()
    jwk1 = pem_to_jwk(pk1, "kid-a")
    jwk2 = pem_to_jwk(pk2, "kid-b")
    doc = _discovery([jwk1, jwk2])
    txt = {"kid": "kid-b", "fingerprint": _fp_for(jwk2)}
    verify_dns_match(doc, txt)


def test_verify_kid_mismatch_fails_even_when_fp_matches():
    _, pk = generate_key_pair()
    jwk = pem_to_jwk(pk, "kid-real")
    doc = _discovery([jwk])
    txt = {"kid": "kid-different", "fingerprint": _fp_for(jwk)}
    with pytest.raises(Exception):
        verify_dns_match(doc, txt)


def test_verify_mismatch_raises():
    _, pk = generate_key_pair()
    jwk = pem_to_jwk(pk, "kid-1")
    doc = _discovery([jwk])
    txt = {
        "kid": None,
        "fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }
    with pytest.raises(Exception):
        verify_dns_match(doc, txt)


def test_txt_record_name_strips_trailing_dot():
    assert txt_record_name("example.com") == "_agentpin.example.com"
    assert txt_record_name("example.com.") == "_agentpin.example.com"
