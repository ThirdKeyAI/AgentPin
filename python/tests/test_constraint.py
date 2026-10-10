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


class TestMergeConstraints:
    """AP-15."""

    def test_omitted_fields_inherit_and_widening_fails(self):
        import pytest

        from agentpin.constraint import merge_constraints

        disc = {
            "allowed_domains": ["*.client-corp.com"],
            "denied_domains": ["internal.client-corp.com"],
            "rate_limit": "100/hour",
            "data_classification_max": "confidential",
            "ip_allowlist": ["203.0.113.0/24", "198.51.100.0/24"],
            "valid_hours": {"start": "08:00", "end": "18:00", "timezone": "UTC"},
        }
        assert merge_constraints(disc, None) == disc
        merged = merge_constraints(
            disc,
            {
                "rate_limit": "1/minute",
                "data_classification_max": "internal",
                "denied_domains": ["staging.client-corp.com"],
            },
        )
        assert merged["allowed_domains"] == disc["allowed_domains"]
        assert merged["rate_limit"] == "1/minute"
        assert merged["data_classification_max"] == "internal"
        assert merged["denied_domains"] == ["internal.client-corp.com", "staging.client-corp.com"]
        assert merged["ip_allowlist"] == disc["ip_allowlist"]
        assert merged["valid_hours"] == disc["valid_hours"]
        for widen in [
            {"allowed_domains": ["evil.com"]},
            {"rate_limit": "1000/hour"},
            {"rate_limit": "unlimited/hour"},
            {"data_classification_max": "restricted"},
            {"ip_allowlist": ["0.0.0.0/0"]},
            {"valid_hours": {"start": "07:00", "end": "18:00", "timezone": "UTC"}},
            {"valid_hours": {"start": "09:00", "end": "17:00", "timezone": "America/New_York"}},
        ]:
            with pytest.raises(ValueError):
                merge_constraints(disc, widen)
        narrow = merge_constraints(
            disc,
            {
                "allowed_domains": ["api.client-corp.com"],
                "ip_allowlist": ["203.0.113.0/24"],
                "valid_hours": {"start": "09:00", "end": "17:00", "timezone": "UTC"},
            },
        )
        assert narrow["allowed_domains"] == ["api.client-corp.com"]
        assert narrow["rate_limit"] == "100/hour"
        with pytest.raises(ValueError):
            merge_constraints(None, {"rate_limit": "x/hour"})
        assert merge_constraints(None, None) is None

    def test_parse_rate_limit_rejects_junk(self):
        assert parse_rate_limit("unlimited/hour") is None
        assert parse_rate_limit("-5/hour") is None
        assert parse_rate_limit("+5/hour") is None
        assert parse_rate_limit(" 5/hour") is None
