"""Tests for domain normalization (AP-3, AP-10, AP-12)."""

import pytest

from agentpin.domain import normalize_domain, validate_https_url_for_domain
from agentpin.types import AgentPinError


@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("Example.Com.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("XN--BCHER-KVA.example", "xn--bcher-kva.example"),
        ("localhost", "localhost"),
        ("a-b.c1.example", "a-b.c1.example"),
    ],
)
def test_normalize_canonicalizes(value, expected):
    assert normalize_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "", ".", "..", "../../tmp/x", "/srv/uploads/x", "example.com/path",
        "example.com\\evil", "https://example.com", "user@example.com",
        "example.com:8443", "127.0.0.1", "127.0.0.1:8443", "[::1]", "::1",
        "example.com?x=1", "example.com#frag", " example.com", "example.com ",
        "exa mple.com", "example..com", ".example.com", "-example.com",
        "example-.com", "exam_ple.com", "example.com..", "a%2eb", "\x00example.com",
        "a" * 64 + ".example", "abcdefghij." * 26 + "example", None, 42,
    ],
)
def test_normalize_rejects_non_hostnames(value):
    with pytest.raises(AgentPinError):
        normalize_domain(value)


def test_validate_https_url_for_domain_accepts_same_host():
    validate_https_url_for_domain("https://example.com/.well-known/agent-identity-revocations.json", "example.com")
    validate_https_url_for_domain("https://EXAMPLE.com/x", "example.com.")


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com/x", "https://other.com/x", "https://example.com:8443/x",
        "https://user@example.com/x", "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/x", "https://example.com/x#frag", "ftp://example.com/x", "not a url",
    ],
)
def test_validate_https_url_for_domain_rejects(value):
    with pytest.raises(AgentPinError):
        validate_https_url_for_domain(value, "example.com")
