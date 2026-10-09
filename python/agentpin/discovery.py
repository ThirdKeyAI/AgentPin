"""Discovery document handling for AgentPin."""

from typing import Any, Iterable, List, Optional

from .constraint import domain_pattern_matches
from .domain import normalize_domain, validate_https_url_for_domain
from .net import fetch_json_bounded
from .types import AgentPinError, ErrorCode


def build_discovery_document(
    entity: str,
    entity_type: str,
    public_keys: List[dict],
    agents: List[dict],
    max_delegation_depth: int,
    updated_at: str,
    a2a_endpoint: Optional[str] = None,
) -> dict:
    """Build a new discovery document.

    ``a2a_endpoint`` (v0.3.0) optionally specifies the URL of the entity's
    A2A AgentCard, enabling cross-protocol discovery.
    """
    doc = {
        "agentpin_version": "0.1",
        "entity": entity,
        "entity_type": entity_type,
        "public_keys": public_keys,
        "agents": agents,
        "revocation_endpoint": f"https://{entity}/.well-known/agent-identity-revocations.json",
        "max_delegation_depth": max_delegation_depth,
        "updated_at": updated_at,
    }
    if a2a_endpoint is not None:
        doc["a2a_endpoint"] = a2a_endpoint
    return doc


# ---------------------------------------------------------------------------
# v0.3.0: AllowedDomains helpers
# ---------------------------------------------------------------------------


class AllowedDomains:
    """Helpers for the ``allowed_domains`` constraint as a typed allow-list.

    v0.3.0, made a proper tri-state in v0.4 (AP-6). Three states: ``None`` is
    *unrestricted* (the field is absent on the wire); a list, including an
    empty one, is *restricted* to the listed literals and ``*.`` patterns
    (spec §5.5). "No restriction" and "restricted to nothing" are therefore
    distinct: the intersection of two disjoint allow-lists is ``[]``, which
    allows nothing and is never re-interpreted as unrestricted. Mirrors the
    ``AllowedDomains`` type in the Rust SDK.

    All methods are static — instances are plain ``list[str]`` or ``None``.
    """

    @staticmethod
    def unrestricted() -> None:
        """The unrestricted allow-list (``None``)."""
        return None

    @staticmethod
    def from_domains(iter_: Iterable[str]) -> List[str]:
        """Construct a restricted list from any iterable; empty allows nothing."""
        return [str(d) for d in iter_]

    @staticmethod
    def is_unrestricted(list_: Optional[List[str]]) -> bool:
        """``True`` when the list places no restriction (``None``)."""
        return list_ is None

    @staticmethod
    def allows(list_: Optional[List[str]], domain: str) -> bool:
        """``True`` when ``domain`` is allowed: unrestricted allows all, entries use
        §5.5 patterns, ``[]`` allows nothing."""
        if list_ is None:
            return True
        return any(domain_pattern_matches(p, domain) for p in list_)

    @staticmethod
    def intersect(a: Optional[List[str]], b: Optional[List[str]]) -> Optional[List[str]]:
        """Intersection of two allow-lists.

        ``unrestricted ∩ X = X``; otherwise the entries of either list that are
        allowed by the other (so ``*.corp.com ∩ api.corp.com = api.corp.com``).
        Disjoint lists yield ``[]``, which allows nothing.
        """
        if a is None:
            return None if b is None else list(b)
        if b is None:
            return list(a)
        out: List[str] = []
        for d in a:
            if AllowedDomains.allows(b, d) and d not in out:
                out.append(d)
        for d in b:
            if AllowedDomains.allows(a, d) and d not in out:
                out.append(d)
        return out

    @staticmethod
    def from_constraints(constraints: Optional[dict]) -> Optional[List[str]]:
        """Pull the typed list from a constraints dict.

        Returns ``unrestricted()`` when constraints are ``None`` or have no
        ``allowed_domains`` field, and a copy of the list (including an empty
        one) when present.
        """
        if not constraints:
            return AllowedDomains.unrestricted()
        ad = constraints.get("allowed_domains")
        if ad is None:
            return AllowedDomains.unrestricted()
        return list(ad)


def validate_discovery_document(doc: dict, expected_entity: str) -> None:
    """Validate a discovery document's basic structural requirements.

    Raises:
        AgentPinError: on validation failure
    """
    if doc.get("agentpin_version") != "0.1":
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Unsupported version: {doc.get('agentpin_version')}")

    # Compare entity and the expected domain in normalized form (AP-3).
    expected = normalize_domain(expected_entity)
    try:
        entity = normalize_domain(doc.get("entity"))
    except AgentPinError as e:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Invalid entity: {e}") from None
    if entity != expected:
        raise AgentPinError(
            ErrorCode.DOMAIN_MISMATCH,
            f"Discovery entity '{doc.get('entity')}' does not match expected '{expected_entity}'",
        )
    # Endpoints the verifier may fetch must be https on the entity's own
    # host (AP-12; spec §17 for a2a_endpoint).
    if doc.get("revocation_endpoint") is not None:
        try:
            validate_https_url_for_domain(doc.get("revocation_endpoint"), entity)
        except AgentPinError as e:
            raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Invalid revocation_endpoint: {e}") from None
    if doc.get("a2a_endpoint") is not None:
        try:
            validate_https_url_for_domain(doc.get("a2a_endpoint"), entity)
        except AgentPinError as e:
            raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Invalid a2a_endpoint: {e}") from None

    if not doc.get("public_keys"):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Discovery document must have at least one public key")

    if doc.get("max_delegation_depth", 0) > 3:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "max_delegation_depth must be 0-3")


def find_key_by_kid(doc: dict, kid: str) -> Optional[dict]:
    """Find a public key by kid in a discovery document."""
    for k in doc.get("public_keys", []):
        if k.get("kid") == kid:
            return k
    return None


def find_agent_by_id(doc: dict, agent_id: str) -> Optional[dict]:
    """Find an agent declaration by agent_id."""
    for a in doc.get("agents", []):
        if a.get("agent_id") == agent_id:
            return a
    return None


def fetch_discovery_document(domain: str, **fetch_opts: Any) -> dict:
    """Fetch a discovery document from a domain over HTTPS.

    No redirects, 10 s timeout, 1 MiB body cap, JSON content type required
    (see :mod:`agentpin.net`). ``fetch_opts`` are forwarded to
    :func:`agentpin.net.fetch_json_bounded`.
    """
    domain = normalize_domain(domain)
    url = f"https://{domain}/.well-known/agent-identity.json"
    doc = fetch_json_bounded(url, **fetch_opts)
    if doc is None:
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"HTTP 404 fetching {url}")
    if not isinstance(doc, dict):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Discovery document from {url} is not an object")
    validate_discovery_document(doc, domain)
    return doc
