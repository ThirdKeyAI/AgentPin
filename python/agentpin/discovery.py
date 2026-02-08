"""Discovery document handling for AgentPin."""

from typing import List, Optional

from .types import AgentPinError, ErrorCode


def build_discovery_document(
    entity: str,
    entity_type: str,
    public_keys: List[dict],
    agents: List[dict],
    max_delegation_depth: int,
    updated_at: str,
) -> dict:
    """Build a new discovery document."""
    return {
        "agentpin_version": "0.1",
        "entity": entity,
        "entity_type": entity_type,
        "public_keys": public_keys,
        "agents": agents,
        "revocation_endpoint": f"https://{entity}/.well-known/agent-identity-revocations.json",
        "max_delegation_depth": max_delegation_depth,
        "updated_at": updated_at,
    }


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
