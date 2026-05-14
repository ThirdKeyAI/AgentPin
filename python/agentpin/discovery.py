"""Discovery document handling for AgentPin."""

from typing import Iterable, List, Optional

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

    Convention: an empty list means *unrestricted* (all domains trusted); a
    non-empty list restricts the agent to exactly those domains. Mirrors the
    ``AllowedDomains`` type in the Rust SDK.

    All methods are static — instances are plain ``list[str]``.
    """

    @staticmethod
    def unrestricted() -> List[str]:
        """Construct an empty (unrestricted) list."""
        return []

    @staticmethod
    def from_domains(iter_: Iterable[str]) -> List[str]:
        """Construct from any iterable of strings."""
        return [str(d) for d in iter_]

    @staticmethod
    def is_unrestricted(list_: Optional[List[str]]) -> bool:
        """``True`` when the list is empty (no restriction)."""
        return not list_

    @staticmethod
    def allows(list_: Optional[List[str]], domain: str) -> bool:
        """``True`` when ``domain`` is allowed under this list."""
        return AllowedDomains.is_unrestricted(list_) or domain in list_

    @staticmethod
    def intersect(a: Optional[List[str]], b: Optional[List[str]]) -> List[str]:
        """Intersection of two allow-lists. ``unrestricted ∩ X = X``."""
        if AllowedDomains.is_unrestricted(a):
            return list(b or [])
        if AllowedDomains.is_unrestricted(b):
            return list(a or [])
        b_set = set(b or [])
        return [d for d in a if d in b_set]

    @staticmethod
    def from_constraints(constraints: Optional[dict]) -> List[str]:
        """Pull the typed list from a constraints dict.

        Returns ``unrestricted()`` when constraints are ``None`` or have no
        ``allowed_domains`` field.
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

    if doc.get("entity") != expected_entity:
        raise AgentPinError(
            ErrorCode.DOMAIN_MISMATCH,
            f"Discovery entity '{doc.get('entity')}' does not match expected '{expected_entity}'",
        )

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


def fetch_discovery_document(domain: str) -> dict:
    """Fetch a discovery document from a domain over HTTPS."""
    import requests

    url = f"https://{domain}/.well-known/agent-identity.json"
    resp = requests.get(url, headers={"Accept": "application/json"}, allow_redirects=False, timeout=10)

    if resp.is_redirect or resp.is_permanent_redirect:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            f"Redirect detected fetching {url} (status {resp.status_code}). Redirects are not allowed.",
        )

    if not resp.ok:
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"HTTP {resp.status_code} fetching {url}")

    doc = resp.json()
    validate_discovery_document(doc, domain)
    return doc
