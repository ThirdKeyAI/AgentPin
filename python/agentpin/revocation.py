"""Revocation document handling for AgentPin."""

from datetime import datetime, timezone

from .types import AgentPinError, ErrorCode


def build_revocation_document(entity: str) -> dict:
    """Build an empty revocation document."""
    return {
        "agentpin_version": "0.1",
        "entity": entity,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "revoked_credentials": [],
        "revoked_agents": [],
        "revoked_keys": [],
    }


def add_revoked_credential(doc: dict, jti: str, reason: str) -> None:
    """Add a revoked credential to the document."""
    doc["revoked_credentials"].append({
        "jti": jti,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    })
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()


def add_revoked_agent(doc: dict, agent_id: str, reason: str) -> None:
    """Add a revoked agent to the document."""
    doc["revoked_agents"].append({
        "agent_id": agent_id,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    })
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()


def add_revoked_key(doc: dict, kid: str, reason: str) -> None:
    """Add a revoked key to the document."""
    doc["revoked_keys"].append({
        "kid": kid,
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    })
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()


def check_revocation(doc: dict, jti: str, agent_id: str, kid: str) -> None:
    """Check if a credential, agent, or key is revoked.

    Raises:
        AgentPinError: if revoked
    """
    for rc in doc.get("revoked_credentials", []):
        if rc["jti"] == jti:
            raise AgentPinError(ErrorCode.CREDENTIAL_REVOKED, f"Credential {jti} revoked: {rc['reason']}")

    for ra in doc.get("revoked_agents", []):
        if ra["agent_id"] == agent_id:
            raise AgentPinError(ErrorCode.AGENT_INACTIVE, f"Agent {agent_id} revoked: {ra['reason']}")

    for rk in doc.get("revoked_keys", []):
        if rk["kid"] == kid:
            raise AgentPinError(ErrorCode.KEY_REVOKED, f"Key {kid} revoked: {rk['reason']}")


def fetch_revocation_document(url: str) -> dict:
    """Fetch a revocation document from a URL."""
    import requests

    resp = requests.get(url, headers={"Accept": "application/json"}, timeout=10)

    if not resp.ok:
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"HTTP {resp.status_code} fetching {url}")

    return resp.json()
