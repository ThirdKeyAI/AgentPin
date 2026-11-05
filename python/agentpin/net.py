"""Hardened HTTP fetching shared by every network resolver.

Every outbound request made by this package goes through
:func:`fetch_json_bounded`, which enforces the network defaults the spec and
the security review require (AP-7, AP-12, AP-13): redirects are never
followed, a request timeout bounds stalls, the response body is capped both
by ``Content-Length`` and while streaming, the response must carry a JSON
``Content-Type``, and error strings are generic (URL and failure class, never
transport detail).
"""

import http.client
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple, Union

from .types import AgentPinError, ErrorCode

DEFAULT_TIMEOUT_SECS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 1 << 20


def _default_http_get(url: str, **kwargs: Any) -> Any:
    import requests  # local import keeps `requests` an optional dependency

    return requests.get(url, **kwargs)


#: The GET implementation used by :func:`fetch_json_bounded`. Replaceable in
#: tests. It must accept ``url`` plus ``headers``, ``stream``,
#: ``allow_redirects`` and ``timeout`` keyword arguments and return an object
#: with ``status_code``, ``headers`` (mapping) and ``iter_content(chunk_size)``.
http_get: Callable[..., Any] = _default_http_get


def _is_json_content_type(value: Optional[str]) -> bool:
    if not isinstance(value, str):
        return False
    media = value.split(";")[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def _fail(message: str) -> AgentPinError:
    return AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, message)


def fetch_json_bounded(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECS,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    http_get_impl: Optional[Callable[..., Any]] = None,
) -> Optional[Any]:
    """GET ``url`` and return its parsed JSON body, or ``None`` on HTTP 404.

    Rejects redirects, non-success statuses, non-JSON content types and
    bodies larger than ``max_bytes``.
    """
    get = http_get_impl or http_get
    try:
        resp = get(
            url,
            headers={"Accept": "application/json"},
            stream=True,
            allow_redirects=False,
            timeout=timeout,
        )
    except Exception:
        raise _fail(f"Failed to fetch {url}") from None

    try:
        status = int(getattr(resp, "status_code", 0))
        if 300 <= status < 400:
            raise _fail(f"Redirect rejected fetching {url} (status {status})")
        if status == 404:
            return None
        if not 200 <= status < 300:
            raise _fail(f"HTTP {status} fetching {url}")
        headers = getattr(resp, "headers", {}) or {}
        if not _is_json_content_type(headers.get("Content-Type") or headers.get("content-type")):
            raise _fail(f"Response from {url} is not application/json")
        content_length = headers.get("Content-Length") or headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > max_bytes:
                    raise _fail(f"Response from {url} exceeds {max_bytes} bytes")
            except ValueError:
                raise _fail(f"Invalid Content-Length from {url}") from None
        chunks = []
        total = 0
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise _fail(f"Response from {url} exceeds {max_bytes} bytes")
                chunks.append(chunk)
        except AgentPinError:
            raise
        except Exception:
            raise _fail(f"Failed to read response from {url}") from None
        try:
            return json.loads(b"".join(chunks).decode("utf-8"))
        except Exception:
            raise _fail(f"Invalid JSON from {url}") from None
    finally:
        close = getattr(resp, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Fetching client-supplied URLs (Web Bot Auth key directories)
# ---------------------------------------------------------------------------

_V4_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",  # "this network", includes unspecified
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, includes broadcast
    )
]
_V6_BLOCKED = [
    ipaddress.ip_network(n)
    for n in (
        "::/128",
        "::1/128",
        "ff00::/8",
        "fc00::/7",
        "fe80::/10",
        "2001:db8::/32",
        "64:ff9b::/32",
    )
]


def is_non_public(ip: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]) -> bool:
    """``True`` for addresses a server-side fetch driven by a client-supplied
    URL must never reach: loopback, private, link-local, CGNAT, multicast,
    documentation, unspecified and reserved ranges. IPv4-mapped IPv6
    addresses are judged by their IPv4 address."""
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_non_public(addr.ipv4_mapped)
        return any(addr in n for n in _V6_BLOCKED)
    return any(addr in n for n in _V4_BLOCKED)


@dataclass
class FetchedResponse:
    """A response read by :func:`fetch_bounded`."""

    status: int
    #: Header fields, lowercase names, in order.
    headers: List[Tuple[str, str]]
    body: bytes


def _resolve(host: str, port: int, public_only: bool) -> List[str]:
    """Resolve ``host`` once and return the addresses to connect to."""
    literal = host[1:-1] if host.startswith("[") else host
    try:
        infos = socket.getaddrinfo(literal, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise _fail(f"Failed to resolve {host}") from None
    addrs: List[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        if public_only and is_non_public(ip):
            continue
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:
        raise _fail(f"Refusing to fetch {host}: it resolves only to non-public addresses")
    return addrs


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to one pre-vetted address, never re-resolving the host."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS to one pre-vetted address; SNI and certificate checks use the host name."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._address = address
        self._server_name = host[1:-1] if host.startswith("[") else host

    def connect(self) -> None:
        sock = socket.create_connection((self._address, self.port), self.timeout)
        ctx = ssl.create_default_context()
        self.sock = ctx.wrap_socket(sock, server_hostname=self._server_name)


def fetch_bounded(
    url: str,
    accept: str,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECS,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    public_only: bool = True,
) -> FetchedResponse:
    """GET ``url`` with no redirects, a total time bound and a byte cap, and
    return status, headers and body for any non-redirect status.

    With ``public_only``, the host is resolved once, non-public addresses
    are dropped (a host with none left is refused), and the connection is
    made to a vetted address, so a second DNS answer cannot redirect it.
    """
    from .httpsig import parse_url

    try:
        u = parse_url(url)
    except ValueError:
        raise _fail(f"Invalid URL {url}") from None
    if u.scheme not in ("http", "https"):
        raise _fail(f"Unsupported URL scheme fetching {url}")
    port = u.port if u.port is not None else (443 if u.scheme == "https" else 80)
    literal = u.host[1:-1] if u.host.startswith("[") else u.host
    try:
        ipaddress.ip_address(literal)
        is_literal = True
    except ValueError:
        is_literal = False
    if public_only and is_literal and is_non_public(literal):
        raise _fail(f"Refusing to fetch non-public address {url}")

    deadline = time.monotonic() + timeout
    addresses = _resolve(u.host, port, public_only)
    target = u.path + ("?" + u.query if u.query is not None else "")
    conn_cls = _PinnedHTTPSConnection if u.scheme == "https" else _PinnedHTTPConnection
    resp = None
    conn = None
    for address in addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        conn = conn_cls(u.host, port, address, remaining)
        try:
            conn.request("GET", target, headers={"Accept": accept, "Accept-Encoding": "identity"})
            resp = conn.getresponse()
            break
        except (OSError, http.client.HTTPException):
            conn.close()
            conn = None
    if resp is None or conn is None:
        raise _fail(f"Failed to fetch {url}")
    try:
        status = resp.status
        if 300 <= status < 400:
            raise _fail(f"Redirect rejected fetching {url} (status {status})")
        headers = [(k.lower(), v) for k, v in resp.getheaders()]
        length = resp.getheader("Content-Length")
        if length is not None:
            if not length.strip().isdigit():
                raise _fail(f"Invalid Content-Length from {url}")
            if int(length) > max_bytes:
                raise _fail(f"Response from {url} exceeds {max_bytes} bytes")
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _fail(f"Timed out reading response from {url}")
            if conn.sock is not None:
                conn.sock.settimeout(remaining)
            try:
                chunk = resp.read1(8192)
            except (OSError, http.client.HTTPException):
                raise _fail(f"Failed to read response from {url}") from None
            if not chunk:
                break
            if len(body) + len(chunk) > max_bytes:
                raise _fail(f"Response from {url} exceeds {max_bytes} bytes")
            body.extend(chunk)
        return FetchedResponse(status, headers, bytes(body))
    finally:
        conn.close()
