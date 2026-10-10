"""Constraint validation for AgentPin."""

import re
from typing import Any, Dict, Optional

from .types import DATA_CLASSIFICATION_ORDER

_COUNT_RE = re.compile(r"^[0-9]+$")


def parse_rate_limit(rate: object) -> Optional[int]:
    """Parse a rate limit string like '100/hour' into requests per hour.

    Returns ``None`` for malformed strings.
    """
    if not isinstance(rate, str):
        return None
    parts = rate.split("/")
    if len(parts) != 2 or not _COUNT_RE.match(parts[0]):
        return None
    count = int(parts[0])
    unit = parts[1]
    if unit == "second":
        return count * 3600
    if unit == "minute":
        return count * 60
    if unit == "hour":
        return count
    return None


def domain_pattern_matches(pattern: object, domain: object) -> bool:
    """Check if a domain pattern matches a domain.

    Supports `*.` wildcard prefix for subdomain matching (spec §5.5).
    """
    if not isinstance(pattern, str) or not isinstance(domain, str):
        return False
    if pattern == domain:
        return True

    if pattern.startswith("*."):
        suffix = pattern[2:]
        return domain.endswith(suffix) and len(domain) > len(suffix) and domain[len(domain) - len(suffix) - 1] == "."

    return False


def constraints_subset_of(discovery_constraints: Optional[dict], credential_constraints: Optional[dict]) -> bool:
    """Check that credential constraints are equal to or more restrictive than discovery defaults."""
    try:
        merge_constraints(discovery_constraints, credential_constraints)
        return True
    except ValueError:
        return False


def _validate_rate_limit_field(rate: object) -> None:
    if rate is not None and parse_rate_limit(rate) is None:
        raise ValueError(f"unparsable rate_limit '{rate}'")


def merge_constraints(discovery: Optional[dict], credential: Optional[dict]) -> Optional[Dict[str, Any]]:
    """Compute the effective constraints of a credential (AP-15).

    The discovery declaration's defaults narrowed by whatever the credential
    declares. Every field is compared; the credential may only narrow, never
    widen, and omitting a field inherits the discovery default instead of
    silently dropping it. An unparsable ``rate_limit`` on either side is a
    violation.

    Returns ``None`` when neither side declares constraints, the merged dict
    otherwise.

    Raises:
        ValueError: when the credential widens a discovery constraint.
    """
    if not discovery and not credential:
        return None
    if not credential:
        return dict(discovery or {})
    if not discovery:
        _validate_rate_limit_field(credential.get("rate_limit"))
        return dict(credential)
    merged: Dict[str, Any] = dict(discovery)

    cred_dc = credential.get("data_classification_max")
    if cred_dc is not None:
        disc_dc = discovery.get("data_classification_max")
        if disc_dc is not None:
            disc_order = DATA_CLASSIFICATION_ORDER.get(disc_dc)
            cred_order = DATA_CLASSIFICATION_ORDER.get(cred_dc)
            if disc_order is None or cred_order is None or cred_order > disc_order:
                raise ValueError(f"data_classification_max {cred_dc} exceeds discovery maximum {disc_dc}")
        merged["data_classification_max"] = cred_dc

    _validate_rate_limit_field(discovery.get("rate_limit"))
    _validate_rate_limit_field(credential.get("rate_limit"))
    cred_rate = credential.get("rate_limit")
    if cred_rate is not None:
        disc_rate = discovery.get("rate_limit")
        if disc_rate is not None and parse_rate_limit(cred_rate) > parse_rate_limit(disc_rate):  # type: ignore[operator]
            raise ValueError(f"rate_limit {cred_rate} exceeds discovery limit {disc_rate}")
        merged["rate_limit"] = cred_rate

    cred_domains = credential.get("allowed_domains")
    if cred_domains is not None:
        if not isinstance(cred_domains, list):
            raise ValueError("allowed_domains must be an array")
        disc_domains = discovery.get("allowed_domains")
        if disc_domains is not None:
            for cd in cred_domains:
                if not any(domain_pattern_matches(d, cd) for d in disc_domains):
                    raise ValueError(f"allowed_domains entry '{cd}' is not covered by discovery allowed_domains")
        merged["allowed_domains"] = list(cred_domains)

    cred_denied = credential.get("denied_domains")
    if cred_denied is not None:
        if not isinstance(cred_denied, list):
            raise ValueError("denied_domains must be an array")
        union = list(discovery.get("denied_domains") or [])
        for d in cred_denied:
            if d not in union:
                union.append(d)
        merged["denied_domains"] = union

    cred_ips = credential.get("ip_allowlist")
    if cred_ips is not None:
        if not isinstance(cred_ips, list):
            raise ValueError("ip_allowlist must be an array")
        disc_ips = discovery.get("ip_allowlist")
        if disc_ips is not None:
            for ip in cred_ips:
                if ip not in disc_ips:
                    raise ValueError(f"ip_allowlist entry '{ip}' is not in discovery ip_allowlist")
        merged["ip_allowlist"] = list(cred_ips)

    cred_hours = credential.get("valid_hours")
    if cred_hours is not None:
        disc_hours = discovery.get("valid_hours")
        if disc_hours is not None:
            if (
                not isinstance(cred_hours, dict)
                or cred_hours.get("timezone") != disc_hours.get("timezone")
                or str(cred_hours.get("start")) < str(disc_hours.get("start"))
                or str(cred_hours.get("end")) > str(disc_hours.get("end"))
            ):
                raise ValueError("valid_hours widens the discovery window")
        merged["valid_hours"] = dict(cred_hours) if isinstance(cred_hours, dict) else cred_hours

    return merged
