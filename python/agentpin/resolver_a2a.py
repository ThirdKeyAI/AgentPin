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
from .resolver_local import card_endpoint_host, derive_discovery_from_card
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
    ) -> None:
        self.timeout = timeout
        self._fetch = fetch
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
        url = f"https://{domain}{AGENT_CARD_PATH}"

        try:
            response = self._do_fetch(url)
        except AgentPinError:
            raise
        except Exception as exc:
            raise AgentPinError(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                f"Failed to fetch {url}: {exc}",
            ) from exc

        # Tolerate both requests.Response (with .ok / .status_code) and
        # custom test stubs that expose either property.
        ok = getattr(response, "ok", None)
        status = getattr(response, "status_code", None)
        if ok is None and status is not None:
            ok = 200 <= status < 300
        if not ok:
            raise AgentPinError(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                f"Failed to fetch {url}: HTTP {status}",
            )

        try:
            card = response.json()
        except Exception as exc:
            raise AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                f"Failed to parse AgentCard at {url}: {exc}",
            ) from exc

        verify_agentpin_extension(card)

        endpoint_host = card_endpoint_host(card)
        if endpoint_host != domain:
            raise AgentPinError(
                ErrorCode.DOMAIN_MISMATCH,
                f"AgentCard at {domain} declares agentpin endpoint host "
                f"{endpoint_host} (mismatch)",
            )

        discovery = derive_discovery_from_card(card)
        with self._lock:
            self._last_card = card
            self._last_domain = domain
        return discovery

    def resolve_revocation(self, _domain: str, _discovery: dict) -> None:
        """A2A AgentCards don't carry revocation data. Always returns ``None``."""
        return None

    def _do_fetch(self, url: str):
        if self._fetch is not None:
            return self._fetch(url)
        import requests  # local import keeps `requests` an optional dep

        return requests.get(
            url,
            headers={"Accept": "application/json"},
            allow_redirects=False,
            timeout=self.timeout,
        )
