"""A2aAgentCardResolver (v0.3.0) — fetches A2A AgentCards over HTTPS.

Mirrors the Rust ``agentpin::resolver_a2a`` module:
    1. GET https://{domain}/.well-known/agent-card.json
    2. Verify the AgentPin extension signature against its embedded JWK
    3. Cross-check that the agentpin endpoint inside the card matches the
       fetched domain (defends against a card pointing at someone else's
       AgentPin discovery)
    4. Derive a DiscoveryDocument so the rest of the AgentPin stack runs
       unchanged
"""

from threading import RLock
from typing import Any, Callable, Optional

from .a2a import verify_agentpin_extension
from .domain import normalize_domain
from .net import fetch_json_bounded
from .discovery import fetch_discovery_document
from .resolver_local import card_endpoint_host, card_key_published_in, derive_discovery_from_card
from .types import AgentPinError, ErrorCode


AGENT_CARD_PATH = "/.well-known/agent-card.json"
DEFAULT_TIMEOUT_SECS = 10.0

_FetchFn = Callable[[str], Any]


class A2aAgentCardResolver:
    """Resolver that fetches an A2A AgentCard from a domain over HTTPS and
    exposes both the original card and the derived discovery document.

    Uses ``requests`` by default; pass ``fetch=...`` to inject a custom
    callable (useful for tests). The callable receives the URL and must
    return an object with ``ok``, ``status_code`` and ``.json()`` attributes
    (matching ``requests.Response``).
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECS,
        fetch: Optional[_FetchFn] = None,
        require_discovery_binding: bool = True,
    ) -> None:
        """``require_discovery_binding`` (default ``True``) implements spec
        §4.10.4 step 5: after the card signature verifies, the domain's
        ``.well-known/agent-identity.json`` is fetched and the card key must
        be published there by thumbprint (AP-4). Disable only when another
        channel establishes the card's provenance."""
        self.timeout = timeout
        self._fetch = fetch
        self.require_discovery_binding = require_discovery_binding
        self._last_card: Optional[dict] = None
        self._last_domain: Optional[str] = None
        self._lock = RLock()

    def last_card(self, domain: str) -> Optional[dict]:
        """Return the last successfully resolved AgentCard for ``domain``,
        or ``None``."""
        with self._lock:
            if self._last_domain != domain:
                return None
            return self._last_card

    def resolve_discovery(self, domain: str) -> dict:
        """Fetch + verify the AgentCard at
        ``https://{domain}/.well-known/agent-card.json`` and return the
        derived discovery document."""
        domain = normalize_domain(domain)
        url = f"https://{domain}{AGENT_CARD_PATH}"

        # No redirects (spec §4.8.5), bounded timeout and body size (AP-7,
        # AP-13). An injected ``fetch`` callable is wrapped so the same
        # status/redirect/size rules apply to it.
        if self._fetch is not None:
            card = fetch_json_bounded(url, timeout=self.timeout, http_get_impl=self._wrapped_fetch)
        else:
            card = fetch_json_bounded(url, timeout=self.timeout)
        if card is None:
            raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"Failed to fetch {url}: HTTP 404")
        if not isinstance(card, dict):
            raise AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Failed to parse AgentCard at {url}")

        verify_agentpin_extension(card)

        endpoint_host = card_endpoint_host(card)
        if endpoint_host != domain:
            raise AgentPinError(
                ErrorCode.DOMAIN_MISMATCH,
                f"AgentCard at {domain} declares agentpin endpoint host "
                f"{endpoint_host} (mismatch)",
            )

        # Spec §4.10.4 step 5 (AP-4): bind the card to the AgentPin identity
        # by requiring its key in the authoritative discovery document.
        if self.require_discovery_binding:
            if self._fetch is not None:
                authoritative = fetch_discovery_document(
                    domain, timeout=self.timeout, http_get_impl=self._wrapped_fetch
                )
            else:
                authoritative = fetch_discovery_document(domain, timeout=self.timeout)
            if not card_key_published_in(authoritative, card):
                raise AgentPinError(
                    ErrorCode.DISCOVERY_INVALID,
                    f"AgentCard key for {domain} is not published in the domain's discovery document",
                )

        discovery = derive_discovery_from_card(card)
        with self._lock:
            self._last_card = card
            self._last_domain = domain
        return discovery

    def resolve_revocation(self, _domain: str, _discovery: dict) -> None:
        """A2A AgentCards don't carry revocation data. Always returns ``None``."""
        return None

    def _wrapped_fetch(self, url: str, **_kwargs: Any) -> Any:
        """Adapt an injected ``fetch(url)`` callable (returning a
        requests-like response, or a stub with ``status_code``/``ok`` and
        ``json()``) to the interface :func:`fetch_json_bounded` expects."""
        assert self._fetch is not None
        response = self._fetch(url)
        return _ResponseAdapter(response)


class _ResponseAdapter:
    """Presents a requests-like or stub response through the minimal
    interface used by :func:`agentpin.net.fetch_json_bounded`."""

    def __init__(self, response: Any) -> None:
        self._response = response
        status = getattr(response, "status_code", None)
        if status is None:
            ok = getattr(response, "ok", False)
            status = 200 if ok else 500
        self.status_code = int(status)
        headers = getattr(response, "headers", None)
        self.headers = dict(headers) if headers else {"Content-Type": "application/json"}
        if "Content-Type" not in self.headers and "content-type" not in self.headers:
            self.headers["Content-Type"] = "application/json"

    def iter_content(self, chunk_size: int = 8192):
        iter_content = getattr(self._response, "iter_content", None)
        if callable(iter_content):
            yield from iter_content(chunk_size=chunk_size)
            return
        import json

        yield json.dumps(self._response.json()).encode("utf-8")

    def close(self) -> None:
        close = getattr(self._response, "close", None)
        if callable(close):
            close()
