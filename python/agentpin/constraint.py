"""Constraint validation for AgentPin."""

from typing import Optional

from .types import DATA_CLASSIFICATION_ORDER


def parse_rate_limit(rate: str) -> Optional[int]:
    """Parse a rate limit string like '100/hour' into requests per hour."""
    parts = rate.split("/")
    if len(parts) != 2:
        return None

    try:
        count = int(parts[0])
    except ValueError:
        return None

    unit = parts[1]
    if unit == "second":
        return count * 3600
    elif unit == "minute":
        return count * 60
    elif unit == "hour":
        return count
    else:
        return None


def domain_pattern_matches(pattern: str, domain: str) -> bool:
    """Check if a domain pattern matches a domain.

    Supports `*.` wildcard prefix for subdomain matching.
    """
    if pattern == domain:
        return True

    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain.endswith(suffix) and len(domain) > len(suffix) and domain[len(domain) - len(suffix) - 1] == "."

    return False


def constraints_subset_of(discovery_constraints: Optional[dict], credential_constraints: Optional[dict]) -> bool:
    """Check that credential constraints are equal to or more restrictive than discovery defaults."""
    if not discovery_constraints:
        return True
    if not credential_constraints:
        return True

    # Data classification: credential max must be <= discovery max
    disc_dc = discovery_constraints.get("data_classification_max")
    cred_dc = credential_constraints.get("data_classification_max")
    if disc_dc and cred_dc:
        disc_order = DATA_CLASSIFICATION_ORDER.get(disc_dc)
        cred_order = DATA_CLASSIFICATION_ORDER.get(cred_dc)
        if disc_order is not None and cred_order is not None and cred_order > disc_order:
            return False

    # Rate limit: credential rate must be <= discovery rate
    disc_rate = discovery_constraints.get("rate_limit")
    cred_rate = credential_constraints.get("rate_limit")
    if disc_rate and cred_rate:
        disc_count = parse_rate_limit(disc_rate)
        cred_count = parse_rate_limit(cred_rate)
        if disc_count is not None and cred_count is not None and cred_count > disc_count:
            return False

    # Allowed domains: credential allowed domains should be a subset of discovery allowed domains
    disc_domains = discovery_constraints.get("allowed_domains")
    cred_domains = credential_constraints.get("allowed_domains")
    if disc_domains and cred_domains:
        for cred_domain in cred_domains:
            if not any(domain_pattern_matches(d, cred_domain) for d in disc_domains):
                return False

    return True
