"""Revocation document handling for AgentPin."""

from datetime import datetime, timezone
from typing import Any, Optional

from .crypto import CTX_REVOCATION, domain_separated_input, sign_data, verify_signature
from .domain import https_url_host, normalize_domain
from .jwk import jwk_to_pem
from .net import fetch_json_bounded
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
    for rc in doc.get("revoked_credentials") or []:
        if isinstance(rc, dict) and rc.get("jti") == jti:
            raise AgentPinError(ErrorCode.CREDENTIAL_REVOKED, f"Credential {jti} revoked: {rc.get('reason')}")

    for ra in doc.get("revoked_agents") or []:
        if isinstance(ra, dict) and ra.get("agent_id") == agent_id:
            raise AgentPinError(ErrorCode.AGENT_INACTIVE, f"Agent {agent_id} revoked: {ra.get('reason')}")

    for rk in doc.get("revoked_keys") or []:
        if isinstance(rk, dict) and rk.get("kid") == kid:
            raise AgentPinError(ErrorCode.KEY_REVOKED, f"Key {kid} revoked: {rk.get('reason')}")


def fetch_revocation_document(url: str, **fetch_opts: Any) -> dict:
    """Fetch a revocation document from a URL.

    Any failure, including HTTP 404, raises so callers fail closed for an
    explicitly declared endpoint.
    """
    doc = fetch_revocation_document_if_present(url, **fetch_opts)
    if doc is None:
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"HTTP 404 fetching {url}")
    return doc


def fetch_revocation_document_if_present(url: str, **fetch_opts: Any) -> Optional[dict]:
    """Fetch a revocation document, returning ``None`` on HTTP 404.

    Used for the spec §8.1 default endpoint when the discovery document
    declares none: an issuer that publishes no revocation document is not an
    error, but any other failure still fails closed.
    """
    # Only https URLs with a domain host are ever fetched, and never through
    # a redirect (AP-12). Same-host binding to the issuer is enforced by the
    # caller / discovery validation.
    https_url_host(url)
    doc = fetch_json_bounded(url, **fetch_opts)
    if doc is not None and not isinstance(doc, dict):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Revocation document from {url} is not an object")
    return doc


# ---------------------------------------------------------------------------
# Signed revocation documents and freshness (design issue 3)
# ---------------------------------------------------------------------------


def revocation_signing_input(doc: dict) -> bytes:
    """The ``agentpin-revocation-v1`` context over the canonical JSON of ``doc``
    with ``signature`` cleared."""
    from .a2a import canonicalize_for_signing

    rest = {k: v for k, v in doc.items() if k != "signature"}
    return domain_separated_input(CTX_REVOCATION, [canonicalize_for_signing(rest).encode("utf-8")])


def sign_revocation_document(doc: dict, private_key_pem: str, kid: str) -> dict:
    """Sign a revocation document in place with a discovery-document key."""
    doc["kid"] = kid
    doc.pop("signature", None)
    doc["signature"] = sign_data(private_key_pem, revocation_signing_input(doc))
    return doc


def verify_revocation_document(doc: dict, discovery: dict) -> None:
    """Validate a revocation document against the discovery document it
    belongs to: wire version, entity binding, and (when present) its
    signature under a key from ``discovery["public_keys"]``.

    Raises ``AgentPinError(DISCOVERY_INVALID)`` on failure.
    """
    if not isinstance(doc, dict):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Revocation document is not an object")
    if doc.get("agentpin_version") != "0.1":
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID, f"Unsupported revocation document version: {doc.get('agentpin_version')}"
        )
    try:
        doc_entity = normalize_domain(doc.get("entity"))
    except AgentPinError as e:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Invalid revocation entity: {e}") from None
    disc_entity = normalize_domain(discovery.get("entity"))
    if doc_entity != disc_entity:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            f"Revocation document entity '{doc.get('entity')}' does not match discovery entity "
            f"'{discovery.get('entity')}'",
        )
    # Structural check (AP-8): every entry must carry its identifying field.
    # An operator who publishes the wrong field name (e.g. "id") must get a
    # hard failure, not a document that silently never matches anything.
    for list_name, field in (
        ("revoked_credentials", "jti"),
        ("revoked_agents", "agent_id"),
        ("revoked_keys", "kid"),
    ):
        entries = doc.get(list_name)
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"{list_name} is not an array")
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(entry.get(field), str) or not entry.get(field):
                raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"{list_name}[{i}] is missing {field}")
    if doc.get("signature") is not None:
        kid = doc.get("kid")
        if not isinstance(kid, str) or not kid:
            raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Signed revocation document has no kid")
        jwk = next((k for k in discovery.get("public_keys", []) if k.get("kid") == kid), None)
        if jwk is None:
            raise AgentPinError(
                ErrorCode.DISCOVERY_INVALID, f"Revocation document kid '{kid}' not found in discovery document"
            )
        if not verify_signature(jwk_to_pem(jwk), revocation_signing_input(doc), str(doc.get("signature"))):
            raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Revocation document signature did not verify")


def check_revocation_freshness(doc: dict, max_age_secs: int) -> None:
    """Reject a document whose ``updated_at`` is unparsable or older than ``max_age_secs``."""
    raw = doc.get("updated_at")
    try:
        updated = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Revocation document updated_at is not RFC 3339") from None
    if updated.tzinfo is None:
        updated = updated.replace(tzinfo=timezone.utc)
    age = int((datetime.now(timezone.utc) - updated).total_seconds())
    if age > max_age_secs:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID, f"Revocation document is stale ({age} seconds old, max {max_age_secs})"
        )
