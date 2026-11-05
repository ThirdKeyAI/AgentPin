"""RFC 9421 HTTP Message Signatures.

Builds signature bases, reads and writes the ``Signature-Input`` and
``Signature`` fields, and signs and verifies with Ed25519 (``alg="ed25519"``)
or RSASSA-PSS SHA-512 (``alg="rsa-pss-sha512"``). This is the layer Web Bot
Auth (:mod:`agentpin.wba`) is built on. Mirrors the Rust
``agentpin::httpsig`` module.

Supported component identifiers: ``@method``, ``@target-uri``,
``@authority``, ``@scheme``, ``@request-target``, ``@path``, ``@query``,
``@query-param`` (with ``name``), ``@status``, and HTTP fields, with the
``key`` (Dictionary member) and ``req`` (related request) parameters.
Identifiers carrying any other parameter (``sf``, ``bs``, ``tr``) are
rejected rather than silently mis-serialized.

The module also carries a minimal, strict RFC 9651 Structured Field parser
and serializer (Dictionary, Inner List, Item and parameters; String, Token,
Integer, Decimal, Boolean, Byte Sequence, Date and Display String).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from typing import Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import unquote_to_bytes

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .types import AgentPinError, ErrorCode

Headers = List[Tuple[str, str]]


def _err(message: str) -> AgentPinError:
    return AgentPinError(ErrorCode.HTTP_SIGNATURE, message)


def _sig_invalid() -> AgentPinError:
    return AgentPinError(ErrorCode.SIGNATURE_INVALID, "Signature verification failed")


def _key_format() -> AgentPinError:
    return AgentPinError(ErrorCode.INVALID_KEY_FORMAT, "Invalid key format")


# ---------------------------------------------------------------------------
# Structured Field Values (RFC 9651)
# ---------------------------------------------------------------------------


class StructuredFieldError(ValueError):
    """A value that is not a valid Structured Field, or cannot be serialized as one."""


@dataclass(frozen=True)
class Token:
    """An sf-token bare item."""

    value: str


@dataclass(frozen=True)
class Date:
    """An sf-date bare item (Unix seconds)."""

    value: int


@dataclass(frozen=True)
class DisplayString:
    """An sf-displaystring bare item."""

    value: str


#: A bare item: ``bool`` (Boolean), ``int`` (Integer), ``Decimal``, ``str``
#: (String), ``Token``, ``bytes`` (Byte Sequence), ``Date`` or ``DisplayString``.
BareItem = Union[bool, int, Decimal, str, Token, bytes, Date, DisplayString]
Params = Dict[str, BareItem]


@dataclass
class Item:
    value: BareItem
    params: Params = field(default_factory=dict)


@dataclass
class InnerList:
    items: List[Item]
    params: Params = field(default_factory=dict)


Member = Union[Item, InnerList]
SfDictionary = Dict[str, Member]

_DIGIT = frozenset("0123456789")
_LCALPHA = "abcdefghijklmnopqrstuvwxyz"
_ALPHA = frozenset(_LCALPHA + _LCALPHA.upper())
_KEY_START = frozenset(_LCALPHA + "*")
_KEY_INNER = frozenset(_LCALPHA + "0123456789_-.*")
_TCHAR = frozenset("!#$%&'*+-.^_`|~") | _ALPHA | _DIGIT
_TOKEN_START = _ALPHA | {"*"}
_TOKEN_INNER = _TCHAR | {":", "/"}
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_LOWER_HEX = frozenset("0123456789abcdef")
_MAX_INT = 999_999_999_999_999


class _Parser:
    def __init__(self, text: str) -> None:
        if not text.isascii():
            raise StructuredFieldError("non-ASCII character")
        self.s = text
        self.i = 0

    def peek(self) -> Optional[str]:
        return self.s[self.i] if self.i < len(self.s) else None

    def take(self) -> Optional[str]:
        c = self.peek()
        if c is not None:
            self.i += 1
        return c

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        while self.peek() in (" ", "\t"):
            self.i += 1

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def key(self) -> str:
        start = self.i
        c = self.peek()
        if c is None or c not in _KEY_START:
            raise StructuredFieldError("expected a key")
        self.i += 1
        while (c := self.peek()) is not None and c in _KEY_INNER:
            self.i += 1
        return self.s[start : self.i]

    def dictionary(self) -> SfDictionary:
        out: SfDictionary = {}
        while not self.eof():
            name = self.key()
            member: Member
            if self.peek() == "=":
                self.i += 1
                member = self.item_or_inner_list()
            else:
                member = Item(True, self.params())
            out[name] = member
            self.skip_ows()
            if self.eof():
                return out
            if self.take() != ",":
                raise StructuredFieldError("expected a comma")
            self.skip_ows()
            if self.eof():
                raise StructuredFieldError("trailing comma")
        return out

    def item_or_inner_list(self) -> Member:
        return self.inner_list() if self.peek() == "(" else self.item()

    def inner_list(self) -> InnerList:
        if self.take() != "(":
            raise StructuredFieldError("expected an inner list")
        items: List[Item] = []
        while not self.eof():
            self.skip_sp()
            if self.peek() == ")":
                self.i += 1
                return InnerList(items, self.params())
            items.append(self.item())
            if self.peek() not in (" ", ")"):
                raise StructuredFieldError("expected a space or ')'")
        raise StructuredFieldError("unterminated inner list")

    def item(self) -> Item:
        value = self.bare_item()
        return Item(value, self.params())

    def params(self) -> Params:
        out: Params = {}
        while self.peek() == ";":
            self.i += 1
            self.skip_sp()
            name = self.key()
            value: BareItem = True
            if self.peek() == "=":
                self.i += 1
                value = self.bare_item()
            out[name] = value
        return out

    def bare_item(self) -> BareItem:
        c = self.peek()
        if c is None:
            raise StructuredFieldError("expected a bare item")
        if c == "-" or c in _DIGIT:
            return self.number()
        if c == '"':
            return self.string()
        if c in _TOKEN_START:
            return self.token()
        if c == ":":
            return self.byte_sequence()
        if c == "?":
            return self.boolean()
        if c == "@":
            self.i += 1
            n = self.number()
            if isinstance(n, Decimal):
                raise StructuredFieldError("date must be an integer")
            return Date(n)
        if c == "%":
            return self.display_string()
        raise StructuredFieldError("unexpected character")

    def number(self) -> Union[int, Decimal]:
        start = self.i
        if self.peek() == "-":
            self.i += 1
        c = self.peek()
        if c is None or c not in _DIGIT:
            raise StructuredFieldError("expected a digit")
        self.i += 1
        digits = 1
        while True:
            c = self.peek()
            if c == ".":
                if digits > 12:
                    raise StructuredFieldError("too many digits before the decimal point")
                self.i += 1
                break
            if c is not None and c in _DIGIT:
                digits += 1
                if digits > 15:
                    raise StructuredFieldError("too many digits")
                self.i += 1
                continue
            return int(self.s[start : self.i])
        frac = 0
        while (c := self.peek()) is not None and c in _DIGIT:
            if frac == 3:
                raise StructuredFieldError("too many digits after the decimal point")
            frac += 1
            self.i += 1
        if frac == 0:
            raise StructuredFieldError("trailing decimal point")
        return Decimal(self.s[start : self.i])

    def string(self) -> str:
        self.i += 1
        out: List[str] = []
        while (c := self.take()) is not None:
            if c == '"':
                return "".join(out)
            if c == "\\":
                n = self.take()
                if n not in ('"', "\\"):
                    raise StructuredFieldError("invalid escape")
                out.append(n)
            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise StructuredFieldError("invalid string character")
            else:
                out.append(c)
        raise StructuredFieldError("unterminated string")

    def token(self) -> Token:
        start = self.i
        self.i += 1
        while (c := self.peek()) is not None and c in _TOKEN_INNER:
            self.i += 1
        return Token(self.s[start : self.i])

    def byte_sequence(self) -> bytes:
        self.i += 1
        end = self.s.find(":", self.i)
        if end < 0:
            raise StructuredFieldError("unterminated byte sequence")
        b64 = self.s[self.i : end]
        self.i = end + 1
        # Padding optional, trailing bits tolerated (as the Rust sfv crate).
        if not _B64_RE.match(b64):
            raise StructuredFieldError("invalid byte sequence")
        body = b64.rstrip("=")
        if len(body) % 4 == 1 or len(b64) - len(body) > (-len(body)) % 4:
            raise StructuredFieldError("invalid byte sequence")
        try:
            return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
        except ValueError:
            raise StructuredFieldError("invalid byte sequence") from None

    def boolean(self) -> bool:
        self.i += 1
        c = self.take()
        if c == "1":
            return True
        if c == "0":
            return False
        raise StructuredFieldError("expected a boolean")

    def display_string(self) -> DisplayString:
        self.i += 1
        if self.take() != '"':
            raise StructuredFieldError("expected a quote")
        out = bytearray()
        while (c := self.take()) is not None:
            if c == '"':
                try:
                    return DisplayString(out.decode("utf-8"))
                except UnicodeDecodeError:
                    raise StructuredFieldError("invalid UTF-8 in display string") from None
            if ord(c) < 0x20 or ord(c) > 0x7E:
                raise StructuredFieldError("invalid display string character")
            if c == "%":
                h = self.s[self.i : self.i + 2]
                if len(h) != 2 or not all(x in _LOWER_HEX for x in h):
                    raise StructuredFieldError("invalid percent escape")
                self.i += 2
                out.append(int(h, 16))
            else:
                out.append(ord(c))
        raise StructuredFieldError("unterminated display string")


def parse_sf_dictionary(text: str) -> SfDictionary:
    """Parse ``text`` as a Structured Field Dictionary (empty text is empty)."""
    p = _Parser(text)
    p.skip_sp()
    out = p.dictionary()
    p.skip_sp()
    if not p.eof():
        raise StructuredFieldError("trailing characters")
    return out


def parse_sf_item(text: str) -> Item:
    """Parse ``text`` as a Structured Field Item."""
    p = _Parser(text)
    p.skip_sp()
    out = p.item()
    p.skip_sp()
    if not p.eof():
        raise StructuredFieldError("trailing characters")
    return out


def _ser_key(k: str) -> str:
    if not k or k[0] not in _KEY_START or any(c not in _KEY_INNER for c in k):
        raise StructuredFieldError(f"invalid key '{k}'")
    return k


def _ser_int(v: int) -> str:
    if abs(v) > _MAX_INT:
        raise StructuredFieldError("integer out of range")
    return str(v)


def _ser_bare(v: BareItem) -> str:
    if isinstance(v, bool):
        return "?1" if v else "?0"
    if isinstance(v, int):
        return _ser_int(v)
    if isinstance(v, Decimal):
        q = v.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
        sign, digits, _exp = q.as_tuple()
        text = "".join(map(str, digits)).rjust(4, "0")
        int_part, frac = text[:-3].lstrip("0") or "0", text[-3:].rstrip("0") or "0"
        if len(int_part) > 12:
            raise StructuredFieldError("decimal out of range")
        return ("-" if sign and q != 0 else "") + f"{int_part}.{frac}"
    if isinstance(v, str):
        if any(ord(c) < 0x20 or ord(c) > 0x7E for c in v):
            raise StructuredFieldError("value is not a valid sf-string")
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, Token):
        t = v.value
        if not t or t[0] not in _TOKEN_START or any(c not in _TOKEN_INNER for c in t):
            raise StructuredFieldError("invalid token")
        return t
    if isinstance(v, bytes):
        return ":" + base64.b64encode(v).decode("ascii") + ":"
    if isinstance(v, Date):
        return "@" + _ser_int(v.value)
    if isinstance(v, DisplayString):
        out = []
        for b in v.value.encode("utf-8"):
            if b in (0x25, 0x22) or b < 0x20 or b > 0x7E:
                out.append(f"%{b:02x}")
            else:
                out.append(chr(b))
        return '%"' + "".join(out) + '"'
    raise StructuredFieldError("unsupported bare item type")


def _ser_params(params: Params) -> str:
    out = []
    for k, v in params.items():
        out.append(";" + _ser_key(k) + ("" if v is True else "=" + _ser_bare(v)))
    return "".join(out)


def serialize_sf_item(item: Item) -> str:
    return _ser_bare(item.value) + _ser_params(item.params)


def serialize_sf_inner_list(inner: InnerList) -> str:
    return "(" + " ".join(serialize_sf_item(i) for i in inner.items) + ")" + _ser_params(inner.params)


def serialize_sf_member(member: Member) -> str:
    """Serialize one Dictionary member value (item or inner list, with its parameters)."""
    if isinstance(member, InnerList):
        return serialize_sf_inner_list(member)
    return serialize_sf_item(member)


def serialize_sf_dictionary(d: SfDictionary) -> str:
    out = []
    for k, m in d.items():
        if isinstance(m, Item) and m.value is True:
            out.append(_ser_key(k) + _ser_params(m.params))
        else:
            out.append(_ser_key(k) + "=" + serialize_sf_member(m))
    return ", ".join(out)


# ---------------------------------------------------------------------------
# URLs (the subset of WHATWG URL parsing the Rust `url` crate applies)
# ---------------------------------------------------------------------------

_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
_C0 = frozenset(chr(i) for i in range(0x20))
_FRAGMENT_SET = _C0 | frozenset(' "<>`')
_QUERY_SET = _C0 | frozenset(" \"#<>'")
_PATH_SET = _C0 | frozenset(' "#<>?`{}')
_USERINFO_SET = _PATH_SET | frozenset("/:;=@[\\]^|")
_FORBIDDEN_HOST = frozenset(" #%/:<>?@[\\]^|\x00\t\n\r")


def _pct(s: str, encode_set: frozenset[str]) -> str:
    out: List[str] = []
    for c in s:
        if c in encode_set or ord(c) > 0x7E:
            out.extend(f"%{b:02X}" for b in c.encode("utf-8"))
        else:
            out.append(c)
    return "".join(out)


def _ipv4_number(part: str) -> Optional[int]:
    if part[:2] in ("0x", "0X"):
        h = part[2:]
        if h == "":
            return 0
        return int(h, 16) if all(c in "0123456789abcdefABCDEF" for c in h) else None
    if len(part) > 1 and part[0] == "0":
        o = part[1:]
        return int(o, 8) if all(c in "01234567" for c in o) else None
    return int(part) if part and all(c in _DIGIT for c in part) else None


def _ipv6_serialize(packed: bytes) -> str:
    """WHATWG IPv6 serialization: hex groups, longest zero run (of 2+) compressed."""
    groups = [int.from_bytes(packed[i : i + 2], "big") for i in range(0, 16, 2)]
    best, best_len, i = -1, 1, 0
    while i < 8:
        j = i
        while j < 8 and groups[j] == 0:
            j += 1
        if j - i > best_len:
            best, best_len = i, j - i
        i = j + 1 if j == i else j
    if best < 0:
        return ":".join(f"{g:x}" for g in groups)
    head = ":".join(f"{g:x}" for g in groups[:best])
    tail = ":".join(f"{g:x}" for g in groups[best + best_len :])
    return f"{head}::{tail}"


def _parse_host(raw: str) -> str:
    if raw.startswith("["):
        if not raw.endswith("]"):
            raise ValueError("invalid IPv6 host")
        try:
            packed = ipaddress.IPv6Address(raw[1:-1]).packed
        except ValueError:
            raise ValueError("invalid IPv6 host") from None
        return "[" + _ipv6_serialize(packed) + "]"
    host = unquote_to_bytes(raw).decode("utf-8", "replace")
    if not host.isascii():
        try:
            import idna  # provided transitively by requests

            host = idna.encode(host, uts46=True).decode("ascii")
        except Exception:
            raise ValueError("invalid host") from None
    host = host.lower()
    if not host or any(c in _FORBIDDEN_HOST or c == "\x7f" for c in host):
        raise ValueError("invalid host")
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts = parts[:-1]
    last = parts[-1]
    if last and (all(c in _DIGIT for c in last) or _ipv4_number(last) is not None and last[:2] in ("0x", "0X")):
        nums = [_ipv4_number(p) for p in parts]
        if len(nums) > 4 or any(n is None for n in nums):
            raise ValueError("invalid IPv4 host")
        vals = [n for n in nums if n is not None]
        if any(n > 255 for n in vals[:-1]) or vals[-1] >= 256 ** (5 - len(vals)):
            raise ValueError("invalid IPv4 host")
        ip = vals[-1]
        for idx, n in enumerate(vals[:-1]):
            ip += n * 256 ** (3 - idx)
        return str(ipaddress.IPv4Address(ip))
    return host


def _normalize_path(path: str) -> str:
    segments: List[str] = []
    raw = path[1:].split("/") if path.startswith("/") else [path] if path else []
    for i, seg in enumerate(raw):
        last = i == len(raw) - 1
        low = seg.lower()
        if low in ("..", ".%2e", "%2e.", "%2e%2e"):
            if segments:
                segments.pop()
            if last:
                segments.append("")
        elif low in (".", "%2e"):
            if last:
                segments.append("")
        else:
            segments.append(_pct(seg, _PATH_SET))
    return "/" + "/".join(segments)


@dataclass(frozen=True)
class ParsedUrl:
    """An absolute URL with a host, normalized the way the WHATWG URL standard does."""

    scheme: str
    username: str
    password: Optional[str]
    host: str
    port: Optional[int]
    path: str
    query: Optional[str]
    fragment: Optional[str]

    @property
    def authority(self) -> str:
        """Host (lowercase) and non-default port."""
        return self.host if self.port is None else f"{self.host}:{self.port}"

    def serialize(self, *, query: bool = True, fragment: bool = True) -> str:
        userinfo = ""
        if self.username or self.password:
            userinfo = self.username + (f":{self.password}" if self.password else "") + "@"
        out = f"{self.scheme}://{userinfo}{self.authority}{self.path}"
        if query and self.query is not None:
            out += "?" + self.query
        if fragment and self.fragment is not None:
            out += "#" + self.fragment
        return out

    def __str__(self) -> str:
        return self.serialize()


_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")


def parse_url(raw: str) -> ParsedUrl:
    """Parse an absolute URL with a host. Raises ``ValueError``."""
    if not isinstance(raw, str):
        raise ValueError("URL must be a string")
    s = raw.strip("".join(_C0) + " ").replace("\t", "").replace("\n", "").replace("\r", "")
    m = _SCHEME_RE.match(s)
    if not m:
        raise ValueError("URL has no scheme")
    scheme = m.group(1).lower()
    rest = s[m.end() :]
    fragment: Optional[str] = None
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        fragment = _pct(frag, _FRAGMENT_SET)
    query: Optional[str] = None
    if "?" in rest:
        rest, q = rest.split("?", 1)
        query = _pct(q, _QUERY_SET)
    special = scheme in _DEFAULT_PORTS
    if special:
        rest = rest.replace("\\", "/").lstrip("/")
    elif rest.startswith("//"):
        rest = rest[2:]
    else:
        raise ValueError("URL has no host")
    slash = rest.find("/")
    authority, path = (rest, "") if slash < 0 else (rest[:slash], rest[slash:])
    username, password = "", None
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
        user, sep, pw = userinfo.partition(":")
        username = _pct(user, _USERINFO_SET)
        password = _pct(pw, _USERINFO_SET) if sep and pw else None
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            raise ValueError("invalid IPv6 host")
        host_raw, port_raw = authority[: close + 1], authority[close + 1 :]
        if port_raw and not port_raw.startswith(":"):
            raise ValueError("invalid port")
        port_raw = port_raw[1:]
    else:
        host_raw, _, port_raw = authority.partition(":")
    if not host_raw:
        raise ValueError("URL has no host")
    host = _parse_host(host_raw)
    port: Optional[int] = None
    if port_raw:
        if not all(c in _DIGIT for c in port_raw) or int(port_raw) > 65535:
            raise ValueError("invalid port")
        port = int(port_raw)
        if _DEFAULT_PORTS.get(scheme) == port:
            port = None
    return ParsedUrl(scheme, username, password, host, port, _normalize_path(path), query, fragment)


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------


@dataclass
class HttpRequest:
    """The parts of an HTTP request a signature can cover.

    ``headers`` are ``(name, value)`` pairs in order; names are matched
    case-insensitively.
    """

    method: str
    url: str
    headers: Headers = field(default_factory=list)

    def __post_init__(self) -> None:
        self.parsed_url()

    def parsed_url(self) -> ParsedUrl:
        try:
            return parse_url(self.url)
        except ValueError as e:
            raise _err(f"request URL is not an absolute URL with a host: {e}") from None

    def header(self, name: str, value: str) -> "HttpRequest":
        """Return a copy with one more header field."""
        return HttpRequest(self.method, self.url, [*self.headers, (name, value)])


@dataclass
class HttpResponse:
    """The parts of an HTTP response a signature can cover. ``request`` is
    the request that produced it, for components with the ``req`` parameter."""

    status: int
    headers: Headers = field(default_factory=list)
    request: Optional[HttpRequest] = None


Message = Union[HttpRequest, HttpResponse]


def combined_field(headers: Sequence[Tuple[str, str]], name: str) -> Optional[str]:
    """Combined value of every ``name`` field: each value trimmed, joined with
    ``", "`` (RFC 9421 §2.1). ``None`` when the field is absent."""
    lname = name.lower()
    values = [v.strip() for n, v in headers if n.lower() == lname]
    return ", ".join(values) if values else None


def parse_dictionary_field(headers: Sequence[Tuple[str, str]], name: str) -> SfDictionary:
    """Parse the combined ``name`` field as a Dictionary; absent is empty."""
    v = combined_field(headers, name)
    if v is None:
        return {}
    try:
        return parse_sf_dictionary(v)
    except StructuredFieldError:
        raise _err(f"{name} is not a valid Dictionary") from None


# ---------------------------------------------------------------------------
# Component identifiers
# ---------------------------------------------------------------------------


def encode_query_part(s: str) -> str:
    """Percent-encode with the application/x-www-form-urlencoded set, spaces
    as ``%20`` (RFC 9421 §2.2.8)."""
    out = []
    for b in s.encode("utf-8"):
        c = chr(b)
        if (c.isascii() and c.isalnum()) or c in "*-._":
            out.append(c)
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def _decode_form(s: str) -> str:
    return unquote_to_bytes(s.replace("+", " ")).decode("utf-8", "replace")


@dataclass(frozen=True)
class Component:
    """A covered component identifier."""

    #: Lowercase field name or derived component name (``@authority``).
    name: str
    #: ``key`` parameter: cover one member of a Dictionary field.
    key: Optional[str] = None
    #: ``req`` parameter: resolve against the related request.
    req: bool = False
    #: ``name`` parameter of ``@query-param``: the encoded parameter name.
    query_name: Optional[str] = None

    @classmethod
    def keyed(cls, name: str, key: str) -> "Component":
        """A Dictionary field member, e.g. ``"signature-agent";key="sig1"``."""
        return cls(name, key=key)

    @classmethod
    def of_request(cls, name: str) -> "Component":
        """A component of the related request, e.g. ``"@authority";req``."""
        return cls(name, req=True)

    @classmethod
    def query_param(cls, name: str) -> "Component":
        """One named query parameter; ``name`` is percent-encoded (RFC 9421 §2.2.8)."""
        return cls("@query-param", query_name=encode_query_part(name))

    def to_item(self) -> Item:
        params: Params = {}
        if self.query_name is not None:
            params["name"] = self.query_name
        if self.key is not None:
            params["key"] = self.key
        if self.req:
            params["req"] = True
        return Item(self.name, params)

    def identifier(self) -> str:
        try:
            return serialize_sf_item(self.to_item())
        except StructuredFieldError as e:
            raise _err(str(e)) from None

    @classmethod
    def from_item(cls, item: Item) -> "Component":
        name = item.value
        if not isinstance(name, str):
            raise _err("component identifier is not a String")
        if not name or name != name.lower():
            raise _err(f"component name '{name}' must be lowercase")
        if name == "@signature-params":
            raise _err("@signature-params cannot be covered")
        key: Optional[str] = None
        req = False
        query_name: Optional[str] = None
        for k, v in item.params.items():
            if k == "key":
                if not isinstance(v, str):
                    raise _err("key parameter must be a String")
                if name.startswith("@"):
                    raise _err("key parameter on a derived component")
                key = v
            elif k == "req":
                if v is not True:
                    raise _err("req parameter must be true")
                req = True
            elif k == "name" and name == "@query-param":
                if not isinstance(v, str):
                    raise _err("name parameter must be a String")
                query_name = v
            else:
                raise _err(f"unsupported component parameter '{k}' on '{name}'")
        if (name == "@query-param") != (query_name is not None):
            raise _err("@query-param needs exactly one name parameter")
        return cls(name, key, req, query_name)


def _query_param_value(url: ParsedUrl, name: str) -> str:
    found = []
    for pair in (url.query or "").split("&"):
        if not pair:
            continue
        n, _, v = pair.partition("=")
        if encode_query_part(_decode_form(n)) == name:
            found.append(encode_query_part(_decode_form(v)))
    if not found:
        raise _err(f"query parameter '{name}' is missing")
    if len(found) > 1:
        raise _err(f"query parameter '{name}' occurs more than once")
    return found[0]


def component_value(msg: Message, c: Component) -> str:
    """The value of component ``c`` in ``msg``."""
    if c.req:
        if not isinstance(msg, HttpResponse) or msg.request is None:
            raise _err("req parameter needs a response with its request")
        msg = msg.request

    if c.name.startswith("@"):
        derived = c.name[1:]
        if derived == "status":
            if isinstance(msg, HttpResponse):
                return str(msg.status)
            raise _err("@status is only valid on a response")
        if not isinstance(msg, HttpRequest):
            raise _err(f"{c.name} needs a request")
        url = msg.parsed_url()
        if derived == "method":
            return msg.method
        if derived == "target-uri":
            return url.serialize()
        if derived == "authority":
            return url.authority.lower()
        if derived == "scheme":
            return url.scheme
        if derived == "request-target":
            return url.path if url.query is None else f"{url.path}?{url.query}"
        if derived == "path":
            return url.path or "/"
        if derived == "query":
            return "?" + (url.query or "")
        if derived == "query-param":
            return _query_param_value(url, c.query_name or "")
        raise _err(f"unsupported derived component {c.name}")

    if c.key is None:
        v = combined_field(msg.headers, c.name)
        if v is None:
            raise _err(f"covered field '{c.name}' is missing")
        return v
    d = parse_dictionary_field(msg.headers, c.name)
    member = d.get(c.key)
    if member is None:
        raise _err(f"'{c.name}' has no member '{c.key}'")
    return serialize_sf_member(member)


# ---------------------------------------------------------------------------
# Signature parameters
# ---------------------------------------------------------------------------

#: One ``@signature-params`` parameter for signing, e.g. ``("created", 1)``.
#: Names: ``created``/``expires`` (int), ``keyid``/``alg``/``nonce``/``tag`` (str).
#: Parameters are written in the order given.
Param = Tuple[str, Union[int, str]]

_INT_PARAMS = ("created", "expires")
_STR_PARAMS = ("keyid", "alg", "nonce", "tag")


@dataclass
class SignatureParams:
    """Signature parameters as received."""

    created: Optional[int] = None
    expires: Optional[int] = None
    keyid: Optional[str] = None
    alg: Optional[str] = None
    nonce: Optional[str] = None
    tag: Optional[str] = None


def _build_inner_list(components: Sequence[Component], params: Sequence[Param]) -> InnerList:
    p: Params = {}
    for name, value in params:
        if name in _INT_PARAMS:
            if not isinstance(value, int) or isinstance(value, bool) or abs(value) > _MAX_INT:
                raise _err(f"{name} must be an integer in range")
        elif name in _STR_PARAMS:
            if not isinstance(value, str):
                raise _err(f"{name} must be a string")
        else:
            raise _err(f"unsupported signature parameter '{name}'")
        if name in p:
            raise _err(f"duplicate signature parameter '{name}'")
        p[name] = value
    return InnerList([c.to_item() for c in components], p)


def _read_params(params: Params) -> SignatureParams:
    out = SignatureParams()
    for k, v in params.items():
        if k in _INT_PARAMS:
            if not isinstance(v, int) or isinstance(v, bool):
                raise _err(f"{k} must be an Integer")
            setattr(out, k, v)
        elif k in _STR_PARAMS:
            if not isinstance(v, str):
                raise _err(f"{k} must be a String")
            setattr(out, k, v)
        # Unknown parameters are covered by the signature; ignore them.
    return out


# ---------------------------------------------------------------------------
# Signature base, parsing
# ---------------------------------------------------------------------------


def _signature_base(msg: Message, components: Sequence[Component], inner: InnerList) -> str:
    lines = []
    for c in components:
        value = component_value(msg, c)
        if "\n" in value or "\r" in value:
            raise _err("component value contains a line break")
        lines.append(f"{c.identifier()}: {value}\n")
    try:
        params = serialize_sf_inner_list(inner)
    except StructuredFieldError as e:
        raise _err(str(e)) from None
    return "".join(lines) + '"@signature-params": ' + params


@dataclass
class ParsedSignature:
    """One signature read from ``Signature-Input`` and ``Signature``."""

    label: str
    components: List[Component]
    params: SignatureParams
    signature: bytes
    inner: InnerList = field(repr=False)

    def covers(self, component: Component) -> bool:
        """``True`` if the signature covers ``component``."""
        return component in self.components

    def signature_base(self, msg: Message) -> str:
        """The exact signature base this signature claims to cover."""
        return _signature_base(msg, self.components, self.inner)


def parse_signatures(headers: Sequence[Tuple[str, str]]) -> List[ParsedSignature]:
    """Parse every signature carried in ``headers``. A ``Signature-Input``
    member without a matching ``Signature`` member, or a repeated component,
    is an error."""
    inputs = parse_dictionary_field(headers, "signature-input")
    sigs = parse_dictionary_field(headers, "signature")
    out = []
    for label, entry in inputs.items():
        if not isinstance(entry, InnerList):
            raise _err(f"Signature-Input '{label}' is not an Inner List")
        sig = sigs.get(label)
        if not isinstance(sig, Item):
            raise _err(f"no Signature for label '{label}'")
        if not isinstance(sig.value, bytes):
            raise _err(f"Signature '{label}' is not a Byte Sequence")
        components: List[Component] = []
        for item in entry.items:
            c = Component.from_item(item)
            if c in components:
                raise _err(f"component '{c.name}' is covered twice")
            components.append(c)
        out.append(ParsedSignature(label, components, _read_params(entry.params), sig.value, entry))
    return out


@dataclass(frozen=True)
class SignatureFields:
    """``Signature-Input`` and ``Signature`` member strings for one signature,
    e.g. ``sig1=("@authority");created=1`` and ``sig1=:...:``."""

    signature_input: str
    signature: str


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

#: ``alg`` value for Ed25519.
ALG_ED25519 = "ed25519"
#: ``alg`` value for RSASSA-PSS with SHA-512.
ALG_RSA_PSS_SHA512 = "rsa-pss-sha512"

_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _ed_decompress(raw: bytes) -> Optional[Tuple[int, int]]:
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y = (y & ((1 << 255) - 1)) % _P
    u = (y * y - 1) % _P
    v = (_D * y * y + 1) % _P
    x2 = u * pow(v, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = (_P - x) % _P
    return x, y


def _ed_add(a: Tuple[int, int], b: Tuple[int, int]) -> Tuple[int, int]:
    (x1, y1), (x2, y2) = a, b
    t = _D * x1 * x2 * y1 * y2 % _P
    x3 = (x1 * y2 + y1 * x2) * pow(1 + t, _P - 2, _P) % _P
    y3 = (y1 * y2 + x1 * x2) * pow(1 - t, _P - 2, _P) % _P
    return x3, y3


def _ed_small_order(raw: bytes) -> bool:
    """``True`` when ``raw`` decodes to a point of order dividing 8 (or not at all)."""
    pt = _ed_decompress(raw)
    if pt is None:
        return True
    for _ in range(3):
        pt = _ed_add(pt, pt)
    return pt == (0, 1)


def _int_bytes(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


class PublicKey:
    """A public key that verifies HTTP message signatures: Ed25519 or RSA (PSS)."""

    __slots__ = ("kind", "raw", "n", "e")

    def __init__(self, kind: str, *, raw: bytes = b"", n: bytes = b"", e: bytes = b"") -> None:
        self.kind = kind
        self.raw = raw
        self.n = n
        self.e = e

    @classmethod
    def ed25519(cls, raw: bytes) -> "PublicKey":
        """An Ed25519 key from its 32-byte encoding. Rejects bytes that are not a curve point."""
        if len(raw) != 32 or _ed_decompress(raw) is None:
            raise _key_format()
        return cls("ed25519", raw=bytes(raw))

    @classmethod
    def rsa(cls, n: bytes, e: bytes) -> "PublicKey":
        """An RSA key from big-endian modulus and exponent without leading zeros."""
        return cls("rsa", n=bytes(n), e=bytes(e))

    @classmethod
    def from_cryptography(cls, key: object) -> "PublicKey":
        if isinstance(key, Ed25519PublicKey):
            return cls.ed25519(key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        if isinstance(key, rsa.RSAPublicKey):
            nums = key.public_numbers()
            return cls.rsa(_int_bytes(nums.n), _int_bytes(nums.e))
        raise _key_format()

    @property
    def alg(self) -> str:
        """The RFC 9421 ``alg`` this key signs with."""
        return ALG_ED25519 if self.kind == "ed25519" else ALG_RSA_PSS_SHA512

    def verify(self, data: bytes, sig: bytes) -> None:
        """Verify ``sig`` over ``data``; raises ``AgentPinError(SIGNATURE_INVALID)``.

        Ed25519 verification is strict (small-order keys and ``R`` values
        are rejected, as ``ed25519-dalek``'s ``verify_strict``); RSA keys
        must be 2048 to 8192 bits."""
        try:
            if self.kind == "ed25519":
                if len(sig) != 64 or _ed_small_order(self.raw) or _ed_small_order(sig[:32]):
                    raise _sig_invalid()
                Ed25519PublicKey.from_public_bytes(self.raw).verify(sig, data)
                return
            n, e = int.from_bytes(self.n, "big"), int.from_bytes(self.e, "big")
            if not 2048 <= n.bit_length() <= 8192 or e < 3 or e % 2 == 0 or e.bit_length() > 33:
                raise _sig_invalid()
            if len(sig) != (n.bit_length() + 7) // 8:
                raise _sig_invalid()
            key = rsa.RSAPublicNumbers(e, n).public_key()
            key.verify(sig, data, padding.PSS(padding.MGF1(hashes.SHA512()), 64), hashes.SHA512())
        except AgentPinError:
            raise
        except (InvalidSignature, ValueError, TypeError):
            raise _sig_invalid() from None

    def _material(self) -> Tuple[str, bytes, bytes, bytes]:
        return (self.kind, self.raw, self.n, self.e)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicKey) and self._material() == other._material()

    def __hash__(self) -> int:
        return hash(self._material())

    def __repr__(self) -> str:
        return f"PublicKey({self.kind})"


class PrivateKey:
    """A private key that signs HTTP messages: Ed25519 or RSA (PSS, SHA-512)."""

    __slots__ = ("_key",)

    def __init__(self, key: Union[Ed25519PrivateKey, rsa.RSAPrivateKey]) -> None:
        if isinstance(key, rsa.RSAPrivateKey) and not 2048 <= key.key_size <= 8192:
            raise _key_format()
        if not isinstance(key, (Ed25519PrivateKey, rsa.RSAPrivateKey)):
            raise _key_format()
        self._key = key

    @classmethod
    def generate(cls) -> "PrivateKey":
        """A new Ed25519 key from OS randomness."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: str) -> "PrivateKey":
        """Load a PEM key: PKCS#8 Ed25519 or RSA, or PKCS#1 RSA. RSA keys
        must be 2048 to 8192 bits."""
        try:
            key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
        except Exception:
            raise _key_format() from None
        if not isinstance(key, (Ed25519PrivateKey, rsa.RSAPrivateKey)):
            raise _key_format()
        return cls(key)

    def to_pem(self) -> str:
        """PKCS#8 PEM encoding."""
        return self._key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode("ascii")

    @property
    def alg(self) -> str:
        return ALG_ED25519 if isinstance(self._key, Ed25519PrivateKey) else ALG_RSA_PSS_SHA512

    def public_key(self) -> PublicKey:
        return PublicKey.from_cryptography(self._key.public_key())

    def sign(self, data: bytes) -> bytes:
        if isinstance(self._key, Ed25519PrivateKey):
            return self._key.sign(data)
        return self._key.sign(data, padding.PSS(padding.MGF1(hashes.SHA512()), 64), hashes.SHA512())

    def __repr__(self) -> str:
        return f"PrivateKey({self.alg})"


# ---------------------------------------------------------------------------
# Signing and verifying
# ---------------------------------------------------------------------------


def sign(
    msg: Message,
    label: str,
    components: Sequence[Component],
    params: Sequence[Param],
    key: PrivateKey,
) -> SignatureFields:
    """Sign ``msg`` over ``components`` under ``label``."""
    for i, c in enumerate(components):
        if c in components[:i]:
            raise _err(f"component '{c.name}' is covered twice")
    inner = _build_inner_list(components, params)
    base = _signature_base(msg, components, inner)
    sig = key.sign(base.encode("utf-8"))
    try:
        return SignatureFields(
            serialize_sf_dictionary({label: inner}),
            serialize_sf_dictionary({label: Item(sig)}),
        )
    except StructuredFieldError as e:
        raise _err(str(e)) from None


def verify(msg: Message, sig: ParsedSignature, key: PublicKey) -> None:
    """Verify ``sig`` over ``msg``. A present ``alg`` parameter must match the key.

    Raises ``AgentPinError``: ``SIGNATURE_INVALID`` when the signature does
    not verify, ``HTTP_SIGNATURE`` when the base cannot be built."""
    if sig.params.alg is not None and sig.params.alg != key.alg:
        raise _sig_invalid()
    base = sig.signature_base(msg)
    key.verify(base.encode("utf-8"), sig.signature)


def content_digest(body: bytes) -> str:
    """``Content-Digest`` value for ``body`` using SHA-256 (RFC 9530)."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii") + ":"


def content_digest_matches(headers: Sequence[Tuple[str, str]], body: bytes) -> bool:
    """``True`` when the ``Content-Digest`` field carries a matching ``sha-256`` member."""
    try:
        d = parse_dictionary_field(headers, "content-digest")
    except AgentPinError:
        return False
    m = d.get("sha-256")
    return isinstance(m, Item) and isinstance(m.value, bytes) and m.value == hashlib.sha256(body).digest()
