"""LocalAgentCardStore (v0.3.0) — in-memory A2A AgentCard store.

Mirrors the Rust ``agentpin::resolver_local`` module. For agents that don't
serve HTTP themselves (CLI tools, daemon processes, external agents pushed
into a coordinator at registration time), the coordinator can keep their
AgentCards in memory and look them up by domain without making network
calls — supporting Symbiont's push-based external-agent registration flow.
"""

from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Iterable, Optional

from .a2a import extension_key_thumbprint, verify_agentpin_extension
from .discovery import AllowedDomains
from .domain import https_url_host, normalize_domain
from .jwk import jwk_thumbprint
from .types import AgentPinError, AgentStatus, EntityType, ErrorCode


def _store_key(domain: str) -> str:
    """Store key: the normalized domain when valid, the raw string otherwise."""
    try:
        return normalize_domain(domain)
    except AgentPinError:
        return str(domain)


def card_endpoint_host(card: dict) -> str:
    """Derive the host of the AgentCard's agentpin endpoint URL."""
    ext = card.get("agentpin") if card else None
    if not ext:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID, "AgentCard has no agentpin extension"
        )
    # The endpoint must be https with a domain host and no userinfo, port or
    # fragment; the returned host is normalized (AP-3, AP-12).
    try:
        return https_url_host(ext.get("agentpin_endpoint"))
    except AgentPinError as e:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            f"Invalid agentpin_endpoint URL: {e}",
        ) from None


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
    allowed_domains = (card.get("capabilities") or {}).get("allowed_domains")
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
        "agentpin_version": "0.1",
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


def card_key_published_in(doc: Optional[dict], card: Optional[dict]) -> bool:
    """``True`` when the card's extension key appears, by RFC 7638 thumbprint,
    in ``doc["public_keys"]`` (spec §4.10.4 step 5)."""
    ext = card.get("agentpin") if isinstance(card, dict) else None
    if not ext or not isinstance(doc, dict) or not isinstance(doc.get("public_keys"), list):
        return False
    tp = extension_key_thumbprint(ext)
    return any(isinstance(k, dict) and jwk_thumbprint(k) == tp for k in doc["public_keys"])


class LocalAgentCardStore:
    """In-memory store of pre-registered A2A AgentCards keyed by their
    AgentPin discovery domain.

    Cards are added via :meth:`register` (after the extension signature is
    verified and the trust anchor accepts the key) and looked up via
    :meth:`resolve_discovery`. Pair with a chain resolver to fall back to
    HTTP for unregistered domains.

    Trust anchor (spec §4.10.4 step 5, AP-4, design issue 9): an AgentCard
    is self-certifying, so verifying its signature proves nothing about which
    domain it speaks for. The constructor therefore takes one of:

    - ``trusted_thumbprints`` — allowlist of JWK thumbprints the operator
      verified out of band (the default is an empty allowlist, which refuses
      every registration until :meth:`trust_thumbprint` is called);
    - ``resolver`` — the card key must be published, by thumbprint, in the
      endpoint domain's discovery document as returned by
      ``resolver.resolve_discovery(domain)``;
    - ``unanchored=True`` — explicit opt-out for callers whose registration
      channel already authenticates the registrant for the domain it claims
      (the "documented substitute provenance check" the spec allows).
    """

    def __init__(
        self,
        trusted_thumbprints: Optional[Iterable[str]] = None,
        resolver: Optional[Any] = None,
        unanchored: bool = False,
    ) -> None:
        self._cards: Dict[str, dict] = {}
        self._docs: Dict[str, dict] = {}
        self._lock = RLock()
        self._unanchored = bool(unanchored)
        self._resolver = resolver
        self._trusted: Optional[set] = None if (unanchored or resolver is not None) else set(trusted_thumbprints or [])

    def trust_thumbprint(self, thumbprint: str) -> None:
        """Add a trusted key thumbprint (allowlist-anchored stores only)."""
        with self._lock:
            if self._trusted is None:
                raise AgentPinError(
                    ErrorCode.DISCOVERY_INVALID, "LocalAgentCardStore is not anchored on a thumbprint allowlist"
                )
            self._trusted.add(thumbprint)

    def _check_anchor(self, card: dict, domain: str) -> None:
        tp = extension_key_thumbprint(card["agentpin"])
        if self._unanchored:
            return
        if self._resolver is not None:
            doc = self._resolver.resolve_discovery(domain)
            if not card_key_published_in(doc, card):
                raise AgentPinError(
                    ErrorCode.DISCOVERY_INVALID,
                    f"AgentCard key {tp} is not published in the discovery document for '{domain}'",
                )
            return
        with self._lock:
            trusted = tp in (self._trusted or set())
        if not trusted:
            raise AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                f"AgentCard key {tp} is not a trusted thumbprint for domain '{domain}'",
            )

    def register(self, card: dict) -> None:
        """Register an AgentCard.

        Verifies the extension signature, requires the trust anchor to accept
        the card key for the endpoint's domain, then stores it. Re-registering
        an existing domain replaces the prior entry.
        """
        verify_agentpin_extension(card)
        domain = card_endpoint_host(card)
        self._check_anchor(card, domain)
        doc = derive_discovery_from_card(card)
        with self._lock:
            self._cards[domain] = card
            self._docs[domain] = doc

    def register_for_domain(self, card: dict, expected_domain: str) -> None:
        """:meth:`register`, additionally requiring the card's endpoint host to
        equal ``expected_domain`` (normalized)."""
        expected = normalize_domain(expected_domain)
        host = card_endpoint_host(card)
        if host != expected:
            raise AgentPinError(
                ErrorCode.DOMAIN_MISMATCH,
                f"AgentCard agentpin_endpoint host '{host}' does not match expected domain '{expected}'",
            )
        self.register(card)

    def __len__(self) -> int:
        with self._lock:
            return len(self._cards)

    def is_empty(self) -> bool:
        return len(self) == 0

    def resolve_card(self, domain: str) -> Optional[dict]:
        """Return the raw AgentCard for a domain, or ``None``."""
        with self._lock:
            return self._cards.get(_store_key(domain))

    def resolve_discovery(self, domain: str) -> dict:
        """Resolve the derived discovery document for a domain.

        Raises ``AgentPinError(DISCOVERY_INVALID)`` when the domain isn't
        registered.
        """
        with self._lock:
            doc = self._docs.get(_store_key(domain))
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
        key = _store_key(domain)
        with self._lock:
            had = self._cards.pop(key, None) is not None
            self._docs.pop(key, None)
        return had
