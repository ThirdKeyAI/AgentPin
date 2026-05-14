"""LocalAgentCardStore (v0.3.0) — in-memory A2A AgentCard store.

Mirrors the Rust ``agentpin::resolver_local`` module. For agents that don't
serve HTTP themselves (CLI tools, daemon processes, external agents pushed
into a coordinator at registration time), the coordinator can keep their
AgentCards in memory and look them up by domain without making network
calls — supporting Symbiont's push-based external-agent registration flow.
"""

from datetime import datetime, timezone
from threading import RLock
from typing import Dict, Optional
from urllib.parse import urlparse

from .a2a import verify_agentpin_extension
from .discovery import AllowedDomains
from .types import AgentPinError, AgentStatus, EntityType, ErrorCode


def card_endpoint_host(card: dict) -> str:
    """Derive the host of the AgentCard's agentpin endpoint URL."""
    ext = card.get("agentpin") if card else None
    if not ext:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID, "AgentCard has no agentpin extension"
        )
    parsed = urlparse(ext["agentpin_endpoint"])
    if not parsed.hostname:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "agentpin_endpoint URL has no host",
        )
    return parsed.hostname


def _slug(input_: str) -> str:
    out = []
    for ch in input_:
        if ch.isascii() and ch.isalnum():
            out.append(ch.lower())
        else:
            out.append("-")
    return "".join(out).strip("-")


def derive_discovery_from_card(card: dict) -> dict:
    """Derive a minimal discovery document from a signed A2A AgentCard.

    The card's public-key JWK becomes the sole ``public_keys`` entry; the
    card's name/description/version/skills become a single agent declaration
    so the rest of the AgentPin verification stack (TOFU pinning, revocation,
    capability validation) runs against AgentCards unchanged.
    """
    ext = card.get("agentpin")
    if not ext:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID, "AgentCard has no agentpin extension"
        )
    domain = card_endpoint_host(card)

    capabilities = [s["id"] for s in card.get("skills", [])]
    allowed_domains = (card.get("capabilities") or {}).get("allowed_domains", [])
    constraints = (
        None
        if AllowedDomains.is_unrestricted(allowed_domains)
        else {"allowed_domains": list(allowed_domains)}
    )

    agent_id = f"urn:agentpin:{domain}:{_slug(card['name'])}"
    agent: Dict[str, object] = {
        "agent_id": agent_id,
        "name": card["name"],
        "capabilities": capabilities,
        "status": AgentStatus.ACTIVE,
    }
    if card.get("description") is not None:
        agent["description"] = card["description"]
    if card.get("version") is not None:
        agent["version"] = card["version"]
    if constraints:
        agent["constraints"] = constraints

    return {
        "agentpin_version": "0.3",
        "entity": domain,
        "entity_type": EntityType.BOTH,
        "public_keys": [ext["public_key_jwk"]],
        "agents": [agent],
        "a2a_endpoint": ext["agentpin_endpoint"],
        "max_delegation_depth": 0,
        "updated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
    }


class LocalAgentCardStore:
    """In-memory store of pre-registered A2A AgentCards keyed by their
    AgentPin discovery domain.

    Cards are added via :meth:`register` (after the extension signature is
    verified) and looked up via :meth:`resolve_discovery`. Pair with a chain
    resolver to fall back to HTTP for unregistered domains.
    """

    def __init__(self) -> None:
        self._cards: Dict[str, dict] = {}
        self._docs: Dict[str, dict] = {}
        self._lock = RLock()

    def register(self, card: dict) -> None:
        """Register an AgentCard. Verifies the extension signature before
        storing. Re-registering an existing domain replaces the prior entry."""
        verify_agentpin_extension(card)
        domain = card_endpoint_host(card)
        doc = derive_discovery_from_card(card)
        with self._lock:
            self._cards[domain] = card
            self._docs[domain] = doc

    def __len__(self) -> int:
        with self._lock:
            return len(self._cards)

    def is_empty(self) -> bool:
        return len(self) == 0

    def resolve_card(self, domain: str) -> Optional[dict]:
        """Return the raw AgentCard for a domain, or ``None``."""
        with self._lock:
            return self._cards.get(domain)

    def resolve_discovery(self, domain: str) -> dict:
        """Resolve the derived discovery document for a domain.

        Raises ``AgentPinError(DISCOVERY_INVALID)`` when the domain isn't
        registered.
        """
        with self._lock:
            doc = self._docs.get(domain)
        if doc is None:
            raise AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                f"Domain '{domain}' not in LocalAgentCardStore",
            )
        return doc

    def resolve_revocation(self, _domain: str, _discovery: dict) -> None:
        """The store doesn't carry revocation data — pair with an HTTP/file
        revocation resolver. Always returns ``None``."""
        return None

    def remove(self, domain: str) -> bool:
        """Drop a registered AgentCard. Returns ``True`` when one was removed."""
        with self._lock:
            had = self._cards.pop(domain, None) is not None
            self._docs.pop(domain, None)
        return had
