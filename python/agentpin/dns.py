"""DNS TXT cross-verification at ``_agentpin.{domain}`` (v0.3.0).

Mirrors the Rust ``agentpin::dns`` module. The wire format is

    _agentpin.example.com.  3600  IN  TXT  "v=agentpin1; kid=acme-2026-04; fp=sha256:a1b2c3..."

Semantics:
    - Absent record   -> no effect (DNS TXT is purely additive)
    - Present matching -> verification succeeds
    - Present mismatching / malformed -> hard failure (DISCOVERY_INVALID)

Mismatch is fail-closed because a publisher who *intentionally* published a
TXT record has signaled DNS is part of their trust chain.
"""

from typing import Optional

from .jwk import jwk_thumbprint
from .types import AgentPinError, ErrorCode


VERSION = "agentpin1"
FP_PREFIX = "sha256:"


def parse_txt_record(value: str) -> dict:
    """Parse a raw ``_agentpin.{domain}`` TXT record value.

    Whitespace around ``;`` and ``=`` is tolerated. Field order is not
    significant. Unknown fields are ignored for forward compatibility.

    Returns a dict ``{"version": ..., "kid": str|None, "fingerprint": ...}``.
    Raises ``AgentPinError(DISCOVERY_INVALID)`` on malformed input.
    """
    version: Optional[str] = None
    kid: Optional[str] = None
    fp: Optional[str] = None

    for raw_part in value.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            raise AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                f"DNS TXT field missing '=': {part}",
            )
        k, _, v = part.partition("=")
        k = k.strip().lower()
        v = v.strip()
        if k == "v":
            version = v
        elif k == "kid":
            kid = v
        elif k == "fp":
            fp = v.lower()
        else:
            # Forward-compat: ignore unknown fields.
            continue

    if version is None:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "DNS TXT record missing required 'v' field",
        )
    if version != VERSION:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            f"DNS TXT unsupported version: {version}",
        )
    if fp is None:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "DNS TXT record missing required 'fp' field",
        )
    if not fp.startswith(FP_PREFIX):
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            f"DNS TXT 'fp' must be sha256:<hex>: {fp}",
        )

    return {"version": version, "kid": kid, "fingerprint": fp}


def verify_dns_match(discovery: dict, txt: dict) -> None:
    """Cross-check a parsed TXT record's fingerprint against a discovery doc.

    Raises ``AgentPinError(DISCOVERY_INVALID)`` when no key in
    ``discovery['public_keys']`` matches ``txt['fingerprint']`` (and
    ``txt['kid']`` when present).
    """
    target = txt["fingerprint"].lower()
    for jwk in discovery.get("public_keys", []):
        computed = jwk_thumbprint(jwk).lower()
        if not computed.startswith(FP_PREFIX):
            computed = FP_PREFIX + computed
        if computed != target:
            continue
        txt_kid = txt.get("kid")
        if txt_kid and jwk.get("kid") != txt_kid:
            continue
        return
    raise AgentPinError(
        ErrorCode.DISCOVERY_INVALID,
        f"DNS TXT fingerprint {target} does not match any key in the discovery document",
    )


def txt_record_name(domain: str) -> str:
    """Build the lookup name for a domain: ``_agentpin.{domain}`` with any
    trailing dot stripped."""
    return f"_agentpin.{domain.rstrip('.')}"


def fetch_dns_txt(domain: str) -> Optional[dict]:
    """Fetch and parse the ``_agentpin.{domain}`` TXT record.

    Uses ``dnspython`` (an optional install). Returns:
        - ``None`` when no ``_agentpin`` TXT record exists for the domain
        - parsed record when present
    Raises ``AgentPinError(DISCOVERY_INVALID)`` when the record exists but is
    malformed, or ``AgentPinError(DISCOVERY_FETCH_FAILED)`` for other DNS
    errors.

    When multiple TXT records exist at the same name, the first whose value
    contains ``v=agentpin1`` is used.
    """
    try:
        import dns.resolver
        import dns.exception
    except ImportError as exc:  # pragma: no cover - optional dep
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            "fetch_dns_txt requires the 'dnspython' package",
        ) from exc

    name = txt_record_name(domain)
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.exception.DNSException as exc:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            f"DNS TXT lookup failed for {name}: {exc}",
        ) from exc

    for rdata in answers:
        joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
        if "v=agentpin1" in joined:
            return parse_txt_record(joined)
    return None
