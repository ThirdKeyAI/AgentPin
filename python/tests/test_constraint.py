"""Tests for constraint validation."""

from agentpin.constraint import constraints_subset_of, domain_pattern_matches, parse_rate_limit


class TestParseRateLimit:
    def test_parses_rates(self):
        assert parse_rate_limit("100/hour") == 100
        assert parse_rate_limit("10/minute") == 600
        assert parse_rate_limit("1/second") == 3600

    def test_invalid(self):
        assert parse_rate_limit("invalid") is None
        assert parse_rate_limit("100/day") is None


class TestDomainPatternMatches:
    def test_exact(self):
        assert domain_pattern_matches("example.com", "example.com")

    def test_wildcard(self):
        assert domain_pattern_matches("*.example.com", "sub.example.com")
        assert not domain_pattern_matches("*.example.com", "example.com")

    def test_no_match(self):
        assert not domain_pattern_matches("other.com", "example.com")


class TestConstraintsSubsetOf:
    def test_valid_subset(self):
        disc = {"data_classification_max": "confidential", "rate_limit": "100/hour"}
        cred = {"data_classification_max": "internal", "rate_limit": "50/hour"}
        assert constraints_subset_of(disc, cred)

    def test_data_classification_exceeds(self):
        disc = {"data_classification_max": "confidential"}
        cred = {"data_classification_max": "restricted"}
        assert not constraints_subset_of(disc, cred)

    def test_null_discovery(self):
        assert constraints_subset_of(None, {"rate_limit": "1000/hour"})

    def test_null_credential(self):
        assert constraints_subset_of({"rate_limit": "100/hour"}, None)
