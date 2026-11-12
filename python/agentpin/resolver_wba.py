"""Web Bot Auth key directory resolution over HTTPS.

The ``Signature-Agent`` URL comes from the client, so every fetch is hardened
against SSRF (draft §6.7): https only, no redirects, non-public addresses
refused (and the connection pinned to the vetted address), bounded time,
bytes and key count. A resolved directory replaces the cached copy; a failed
fetch never evicts it, so a directory outage does not revoke an agent's keys
(§6.10). Mirrors the Rust ``agentpin::resolver_wba`` module.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Sequence, Tuple

from . import httpsig, net
from .httpsig import PublicKey
from .net import FetchedResponse
from .types import AgentPinError, ErrorCode
from .wba import (
    DIRECTORY_MEDIA_TYPE,
    Directory,
    find_key,
    normalize_signature_agent,
    verify_directory_response,
)

_ACCEPT = f"{DIRECTORY_MEDIA_TYPE}, application/jwk-set+json, application/json"


@dataclass
class DirectoryFetchOptions:
    """Options for directory fetching."""

    #: Total request timeout in seconds.
    timeout: float = net.DEFAULT_TIMEOUT_SECS
    #: Response body cap (64 KiB).
    max_bytes: int = 64 * 1024
    #: Refuse hosts that are or resolve to non-public addresses. Only
    #: disable for tests against local servers.
    public_only: bool = True
    #: Require ``https`` URLs. Only disable for tests.
    require_https: bool = True
    #: Keep only keys with a valid directory response signature (Appendix
    #: B.1). Default ``False``: a directory the verifier resolved itself is
    #: usable without proof.
    require_proof: bool = False
    #: Cache lifetime (seconds) when the response has no usable ``max-age``.
    default_ttl: float = 3600
    #: Bounds applied to ``max-age``.
    min_ttl: float = 60
    max_ttl: float = 86_400


def _max_age(headers: Sequence[Tuple[str, str]]) -> Optional[int]:
    cc = httpsig.combined_field(headers, "cache-control")
    if cc is None:
        return None
    for directive in cc.split(","):
        k, sep, v = directive.strip().partition("=")
        if sep and k.strip().lower() == "max-age":
            v = v.strip()
            if v.isascii() and v.isdigit():
                return int(v)
    return None


#: The fetch implementation used by :func:`fetch_directory`; replaceable in
#: tests. Called as ``fetch(url, accept, timeout=..., max_bytes=...,
#: public_only=...)``.
Fetcher = Callable[..., FetchedResponse]


def fetch_directory(
    url: str,
    opts: Optional[DirectoryFetchOptions] = None,
    *,
    fetch: Optional[Fetcher] = None,
) -> Tuple[Directory, float]:
    """Fetch and parse the key directory at ``url``. Returns the directory
    and how long (seconds) it may be cached."""
    opts = opts or DirectoryFetchOptions()
    try:
        parsed = httpsig.parse_url(url)
    except ValueError:
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, "invalid directory URL") from None
    if opts.require_https and parsed.scheme != "https":
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"Directory {url} is not https")
    resp = (fetch or net.fetch_bounded)(
        url, _ACCEPT, timeout=opts.timeout, max_bytes=opts.max_bytes, public_only=opts.public_only
    )
    if resp.status != 200:
        raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"HTTP {resp.status} fetching {url}")
    if opts.require_proof:
        directory = verify_directory_response(resp.body, resp.headers, parsed.authority, int(time.time()), 60)
    else:
        directory = Directory.parse(resp.body)
    age = _max_age(resp.headers)
    ttl = float(age) if age is not None else opts.default_ttl
    return directory, min(max(ttl, opts.min_ttl), opts.max_ttl)


@dataclass
class _Cached:
    directory: Directory
    fresh_until: float


class CachingDirectoryResolver:
    """Fetches directories on demand and caches them per URL. Implements
    :class:`~agentpin.wba.KeyLookup` for :func:`~agentpin.wba.verify_request`."""

    def __init__(self, opts: Optional[DirectoryFetchOptions] = None, *, fetch: Optional[Fetcher] = None) -> None:
        self.opts = opts or DirectoryFetchOptions()
        self._fetch = fetch
        self._cache: Dict[str, _Cached] = {}
        self._lock = threading.Lock()

    def _cached(self, url: str, fresh_only: bool) -> Optional[Directory]:
        with self._lock:
            c = self._cache.get(url)
        if c is None or (fresh_only and c.fresh_until <= time.monotonic()):
            return None
        return c.directory

    def insert(self, url: str, directory: Directory, ttl: float = 0) -> None:
        """Seed the cache (``ttl`` 0 records a stale copy used only as a fallback)."""
        with self._lock:
            self._cache[url] = _Cached(directory, time.monotonic() + ttl)

    def lookup(self, signature_agent: str, keyid: str) -> Optional[PublicKey]:
        # Verified requests always pass a normalized https URL; plain URLs are
        # only reachable with `require_https` off (tests).
        url = normalize_signature_agent(signature_agent) if self.opts.require_https else signature_agent
        now = int(time.time())
        cached = self._cached(url, True)
        if cached is not None:
            key = find_key(cached, keyid, now, 60)
            if key is not None:
                return key
        try:
            directory, ttl = fetch_directory(url, self.opts, fetch=self._fetch)
        except AgentPinError:
            # A failed fetch is not evidence: fall back to the last resolved
            # copy (§6.10).
            stale = self._cached(url, False)
            if stale is None:
                raise
            return find_key(stale, keyid, now, 60)
        self.insert(url, directory, ttl)
        return find_key(directory, keyid, now, 60)
