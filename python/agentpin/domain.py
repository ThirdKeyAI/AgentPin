"""Domain-name normalization and validation.

DNS, TLS hostname matching and the HTTP ``Host`` header are case-insensitive,
but the TOFU pin store, the discovery URL and the ``entity == iss``
comparison used to operate on the literal ``iss`` string, so ``EXAMPLE.COM``,
``example.com.`` and the U-label/A-label forms of an IDN were distinct
identities with independent pins (AP-3), and an ``iss`` containing a path,
port or userinfo was interpolated unescaped into URLs (AP-12).
:func:`normalize_domain` is the single choke point applied by every verifier,
resolver and discovery validator.
"""

import re
from urllib.parse import urlsplit

from .types import AgentPinError, ErrorCode

MAX_HOSTNAME_LEN = 253
MAX_LABEL_LEN = 63
_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
_FORBIDDEN = set("/\\?#@:[]%")


def _invalid(reason: str) -> AgentPinError:
    return AgentPinError(ErrorCode.DISCOVERY_INVALID, f"Invalid domain: {reason}")


def _to_ascii(name: str) -> str:
    """IDNA/UTS-46 map ``name`` to A-labels (lowercased)."""
    if name.isascii():
        return name.lower()
    try:
        import idna  # provided transitively by requests

        return idna.encode(name, uts46=True).decode("ascii").lower()
    except ImportError:  # pragma: no cover - fallback when idna is unavailable
        return name.encode("idna").decode("ascii").lower()
    except Exception as exc:  # idna.IDNAError and friends
        raise _invalid(str(exc)) from None


def _looks_like_ipv4(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _validate_ascii_hostname(host: str) -> None:
    if len(host) > MAX_HOSTNAME_LEN:
        raise _invalid("hostname too long")
    if _looks_like_ipv4(host):
        raise _invalid("IP literals are not allowed")
    for label in host.split("."):
        if not label:
            raise _invalid("empty label")
        if len(label) > MAX_LABEL_LEN:
            raise _invalid("label too long")
        if label.startswith("-") or label.endswith("-"):
            raise _invalid("label starts or ends with a hyphen")
        if not _LABEL_RE.match(label):
            raise _invalid("label contains characters outside [a-z0-9-]")


def normalize_domain(value: object) -> str:
    """Normalize a domain name to its canonical lowercase A-label form.

    Exactly one trailing dot is removed; the name is lowercased and IDNA
    mapped; anything that is not a bare hostname is rejected (scheme,
    userinfo, port, path, query, fragment, whitespace, control characters, IP
    literals, empty or over-long labels, leading/trailing hyphens). The result
    is safe as a pin-store key, file name component and URL host.

    Raises ``AgentPinError(DISCOVERY_INVALID)`` on rejection.
    """
    if not isinstance(value, str) or not value:
        raise _invalid("empty")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise _invalid("contains whitespace or control characters")
    if any(ch in _FORBIDDEN for ch in value):
        raise _invalid("not a bare hostname")
    trimmed = value[:-1] if value.endswith(".") else value
    if not trimmed or trimmed.endswith("."):
        raise _invalid("empty label")
    host = _to_ascii(trimmed)
    _validate_ascii_hostname(host)
    return host


def https_url_host(raw_url: object) -> str:
    """Parse ``raw_url``, require https, no userinfo/port/fragment, and return
    its normalized domain host (IP literals rejected)."""
    if not isinstance(raw_url, str) or any(ch.isspace() for ch in raw_url):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Invalid URL")
    try:
        parts = urlsplit(raw_url)
    except ValueError:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Invalid URL") from None
    if parts.scheme != "https":
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "URL must use https")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "URL must not contain userinfo")
    try:
        port = parts.port
    except ValueError:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Invalid URL port") from None
    if port is not None or ":" in parts.netloc.rsplit("@", 1)[-1].lstrip("[").split("]")[-1]:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "URL must not specify a port")
    if parts.fragment:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "URL must not contain a fragment")
    host = parts.hostname
    if not host or parts.netloc.startswith("["):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "URL host must be a domain name")
    return normalize_domain(host)


def validate_https_url_for_domain(raw_url: object, domain: str) -> None:
    """Check that ``raw_url`` is an https URL whose host is exactly ``domain``
    after normalization (AP-12)."""
    expected = normalize_domain(domain)
    host = https_url_host(raw_url)
    if host != expected:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            f"URL host '{host}' does not match domain '{expected}'",
        )


def default_revocation_endpoint(domain: str) -> str:
    """The default revocation endpoint for a domain (spec §8.1)."""
    return f"https://{domain}/.well-known/agent-identity-revocations.json"
