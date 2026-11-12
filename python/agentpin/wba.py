"""Web Bot Auth (WBA) profile of RFC 9421 HTTP Message Signatures.

Implements draft-ietf-webbotauth-httpsig-protocol: agents sign requests with
Ed25519 or RSASSA-PSS, name the HTTPS key directory that publishes the key in
the ``Signature-Agent`` field, and verifiers resolve that directory and check
the signature. This module also binds a WBA signature to an AgentPin identity
(spec §18): the ES256 credential confirms the WBA key with ``cnf.jkt``, and
the issuer's discovery document vouches for the ``Signature-Agent`` URL.
Mirrors the Rust ``agentpin::wba`` module.

WBA uses its own keys. The ES256 credential profile is unchanged, and
credential keys are never used to sign HTTP messages.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple, Union

from . import httpsig
from .domain import normalize_domain
from .httpsig import (
    ALG_ED25519,
    ALG_RSA_PSS_SHA512,
    Component,
    HttpRequest,
    HttpResponse,
    Item,
    Param,
    ParsedSignature,
    PrivateKey,
    PublicKey,
)
from .jwt import base64url_decode, base64url_encode, decode_jwt_unverified
from .nonce import NonceStore
from .pinning import KeyPinStore
from .transport import http_extract_credential
from .types import AgentPinError, ErrorCode, VerificationResult, VerifierConfig

__all__ = [
    "ALG_ED25519",
    "ALG_RSA_PSS_SHA512",
    "TAG",
    "DIRECTORY_TAG",
    "DIRECTORY_PATH",
    "DIRECTORY_MEDIA_TYPE",
    "MAX_DIRECTORY_KEYS",
    "MAX_VALIDITY_SECS",
    "PrivateKey",
    "PublicKey",
    "generate_signing_key",
    "load_signing_key",
    "signing_key_to_pem",
    "thumbprint",
    "Jwk",
    "Directory",
    "well_known_directory",
    "normalize_signature_agent",
    "SignOptions",
    "SignedHeaders",
    "sign_request",
    "VerifyOptions",
    "VerifiedAgent",
    "WbaOutcome",
    "KeyLookup",
    "DirectoryKeyStore",
    "find_key",
    "verify_request",
    "sign_directory_response",
    "verify_directory_response",
    "request_credential",
    "check_binding",
    "BoundAgent",
    "BindingFailure",
    "verify_bound_request",
]

#: ``tag`` value of a Web Bot Auth request signature.
TAG = "web-bot-auth"
#: ``tag`` value of a directory response signature.
DIRECTORY_TAG = "http-message-signatures-directory"
#: Well-known path of a key directory.
DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
#: Media type a well-known key directory is served with.
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
#: Most keys accepted from one directory.
MAX_DIRECTORY_KEYS = 64
#: Longest accepted ``expires - created`` window (24 hours, the draft's
#: recommended ceiling).
MAX_VALIDITY_SECS = 86_400

_I64_MIN, _I64_MAX = -(2**63), 2**63 - 1


def _wba_err(message: str) -> AgentPinError:
    return AgentPinError(ErrorCode.HTTP_SIGNATURE, message)


def _now() -> int:
    return int(time.time())


# ---------------------------------------------------------------------------
# Keys and JWKs
# ---------------------------------------------------------------------------


def generate_signing_key() -> PrivateKey:
    """Generate a new Ed25519 signing key from OS randomness."""
    return PrivateKey.generate()


def load_signing_key(pem: str) -> PrivateKey:
    """Load a signing key from PEM: Ed25519 or RSA (PKCS#8 or PKCS#1)."""
    return PrivateKey.from_pem(pem)


def signing_key_to_pem(key: PrivateKey) -> str:
    """Encode a signing key as a PKCS#8 PEM."""
    return key.to_pem()


def thumbprint(key: PublicKey) -> str:
    """JWK SHA-256 thumbprint, base64url without padding: RFC 8037 for
    Ed25519, RFC 7638 for RSA. This is the WBA ``keyid``."""
    if key.kind == "ed25519":
        canonical = '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % base64url_encode(key.raw)
    else:
        canonical = '{"e":"%s","kty":"RSA","n":"%s"}' % (base64url_encode(key.e), base64url_encode(key.n))
    return base64url_encode(hashlib.sha256(canonical.encode("ascii")).digest())


def _is_i64(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and _I64_MIN <= v <= _I64_MAX


@dataclass
class Jwk:
    """A directory public key as a JWK: OKP/Ed25519 (RFC 8037) or RSA (RFC 7517)."""

    kty: str
    crv: Optional[str] = None
    kid: Optional[str] = None
    x: Optional[str] = None
    n: Optional[str] = None
    e: Optional[str] = None
    use: Optional[str] = None
    alg: Optional[str] = None
    #: Not valid before (Unix seconds).
    nbf: Optional[int] = None
    #: Not valid after (Unix seconds).
    exp: Optional[int] = None

    @classmethod
    def from_public_key(cls, key: PublicKey) -> "Jwk":
        """JWK for ``key``, with ``kid`` set to its thumbprint."""
        if key.kind == "ed25519":
            return cls("OKP", crv="Ed25519", kid=thumbprint(key), x=base64url_encode(key.raw), use="sig")
        return cls("RSA", kid=thumbprint(key), n=base64url_encode(key.n), e=base64url_encode(key.e), use="sig")

    @classmethod
    def from_dict(cls, d: object) -> "Jwk":
        """Read a JWK object. Unknown members are ignored; known members
        must have the right JSON type. Raises ``AgentPinError``."""
        if not isinstance(d, dict) or not isinstance(d.get("kty"), str):
            raise httpsig._key_format()
        kw: Dict[str, Any] = {}
        for name in ("crv", "kid", "x", "n", "e", "use", "alg"):
            v = d.get(name)
            if v is not None and not isinstance(v, str):
                raise httpsig._key_format()
            kw[name] = v
        for name in ("nbf", "exp"):
            v = d.get(name)
            if v is not None and not _is_i64(v):
                raise httpsig._key_format()
            kw[name] = v
        return cls(d["kty"], **kw)

    def to_dict(self) -> Dict[str, Any]:
        """JSON object with absent members omitted, in the Rust SDK's member order."""
        out: Dict[str, Any] = {"kty": self.kty}
        for name in ("crv", "kid", "x", "n", "e", "use", "alg", "nbf", "exp"):
            v = getattr(self, name)
            if v is not None:
                out[name] = v
        return out

    def public_key(self) -> PublicKey:
        """Decode the public key. Accepts Ed25519 OKP keys and RSA keys of
        2048 to 8192 bits with minimal encodings; raises ``AgentPinError``
        for everything else."""

        def b64(v: Optional[str]) -> bytes:
            if v is None:
                raise httpsig._key_format()
            try:
                return base64url_decode(v)
            except ValueError:
                raise httpsig._key_format() from None

        if self.kty == "OKP" and self.crv == "Ed25519":
            return PublicKey.ed25519(b64(self.x))
        if self.kty == "RSA":
            n, e = b64(self.n), b64(self.e)
            # Minimal encodings only (RFC 7518 §6.3.1), so the thumbprint is
            # well defined.
            if not n or n[0] == 0 or not e or e[0] == 0 or len(e) > 4:
                raise httpsig._key_format()
            if not 2048 <= int.from_bytes(n, "big").bit_length() <= 8192:
                raise httpsig._key_format()
            return PublicKey.rsa(n, e)
        raise httpsig._key_format()

    def thumbprint(self) -> Optional[str]:
        """Thumbprint computed from the key material (never taken from
        ``kid``); ``None`` for keys :meth:`public_key` rejects."""
        try:
            return thumbprint(self.public_key())
        except AgentPinError:
            return None

    def usable_at(self, now: int, skew: int) -> bool:
        return (self.nbf is None or now + skew >= self.nbf) and (self.exp is None or now - skew < self.exp)


@dataclass
class Directory:
    """A key directory: a JWK Set of signing keys."""

    keys: List[Jwk] = field(default_factory=list)

    @classmethod
    def from_keys(cls, keys: Sequence[PublicKey]) -> "Directory":
        """Directory publishing the given keys."""
        return cls([Jwk.from_public_key(k) for k in keys])

    @classmethod
    def parse(cls, body: Union[bytes, str]) -> "Directory":
        """Parse a JWK Set. Entries that are not well-formed Ed25519 or RSA
        keys (EC, short RSA, bad values) are skipped; more than
        :data:`MAX_DIRECTORY_KEYS` entries is an error."""
        try:
            raw = json.loads(body)
        except (ValueError, TypeError):
            raise _wba_err("key directory is not a JWK Set") from None
        if not isinstance(raw, dict) or not isinstance(raw.get("keys"), list):
            raise _wba_err("key directory is not a JWK Set")
        if len(raw["keys"]) > MAX_DIRECTORY_KEYS:
            raise _wba_err("key directory has too many keys")
        keys = []
        for entry in raw["keys"]:
            try:
                jwk = Jwk.from_dict(entry)
                jwk.public_key()
            except AgentPinError:
                continue
            keys.append(jwk)
        return cls(keys)

    def to_json(self) -> bytes:
        """Compact JSON body, as served."""
        doc = {"keys": [k.to_dict() for k in self.keys]}
        return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Signature-Agent
# ---------------------------------------------------------------------------


def well_known_directory(domain: str) -> str:
    """The well-known directory URL for ``domain``."""
    return f"https://{domain}{DIRECTORY_PATH}"


def normalize_signature_agent(url: str) -> str:
    """Normalize a Signature-Agent URL into the identifier form the draft
    compares (§5.5): absolute ``https`` URL with a host, query and fragment
    dropped, scheme/host case and default port normalized."""
    try:
        u = httpsig.parse_url(url)
    except ValueError:
        raise _wba_err("Signature-Agent is not an absolute URL") from None
    if u.scheme != "https":
        raise _wba_err("Signature-Agent must be an https URL with a host")
    if u.username or u.password:
        raise _wba_err("Signature-Agent must not carry credentials")
    return u.serialize(query=False, fragment=False)


class _Reject(Exception):
    """Internal: why one signature is invalid."""


def _signature_agent_member(headers: Sequence[Tuple[str, str]], label: str, legacy: bool) -> str:
    """Resolve the Signature-Agent member keyed ``label``. ``legacy`` is set
    when the signature covers the bare ``"signature-agent"`` component, which
    is only valid for the old sf-string form of the field."""
    raw = httpsig.combined_field(headers, "signature-agent")
    if raw is None:
        raise _Reject("request has no Signature-Agent field")
    if legacy:
        if not raw.startswith('"'):
            raise _Reject("Signature-Agent is a Dictionary; cover it with ;key")
        try:
            item = httpsig.parse_sf_item(raw)
        except httpsig.StructuredFieldError:
            raise _Reject("Signature-Agent is not a valid String") from None
    else:
        try:
            d = httpsig.parse_dictionary_field(headers, "signature-agent")
        except AgentPinError as e:
            raise _Reject(str(e)) from None
        member = d.get(label)
        if member is None:
            raise _Reject(f"Signature-Agent has no member '{label}'")
        if not isinstance(member, Item):
            raise _Reject("Signature-Agent member is not an Item")
        item = member
    if item.params:
        raise _Reject("Signature-Agent member carries parameters")
    if not isinstance(item.value, str):
        raise _Reject("Signature-Agent member is not a String")
    try:
        return normalize_signature_agent(item.value)
    except AgentPinError as e:
        raise _Reject(str(e)) from None


# ---------------------------------------------------------------------------
# Signing requests
# ---------------------------------------------------------------------------


def _default_components() -> List[Component]:
    return [Component("@method"), Component("@path")]


@dataclass
class SignOptions:
    """Options for :func:`sign_request`."""

    #: Signature label; also the Signature-Agent member key.
    label: str = "sig1"
    #: ``expires - created``, in seconds (1 to :data:`MAX_VALIDITY_SECS`).
    validity_secs: int = 300
    #: Components covered in addition to ``@authority`` and the
    #: Signature-Agent member. Defaults to ``@method`` and ``@path``, which
    #: narrow a captured signature to one method and resource (§5.2). Add
    #: ``Component("authorization")`` to bind an AgentPin credential.
    components: List[Component] = field(default_factory=_default_components)
    #: Add a random 64-byte ``nonce`` parameter.
    nonce: bool = True
    #: ``created`` timestamp; ``None`` uses the current time.
    created: Optional[int] = None
    #: Send ``Signature-Agent`` in the legacy bare-String form and cover the
    #: bare ``"signature-agent"`` component (draft Appendix E.1.2). Only for
    #: verifiers that predate the Dictionary form.
    legacy_signature_agent: bool = False


@dataclass(frozen=True)
class SignedHeaders:
    """Header fields that carry one WBA signature."""

    signature_agent: str
    signature_input: str
    signature: str

    def to_list(self) -> List[Tuple[str, str]]:
        """``(name, value)`` pairs to append to the request."""
        return [
            ("Signature-Agent", self.signature_agent),
            ("Signature-Input", self.signature_input),
            ("Signature", self.signature),
        ]

    def apply(self, req: HttpRequest) -> None:
        """Append the three fields to ``req`` (in place)."""
        req.headers.extend(self.to_list())


def sign_request(
    req: HttpRequest,
    signing_key: PrivateKey,
    signature_agent: str,
    opts: Optional[SignOptions] = None,
) -> SignedHeaders:
    """Sign ``req`` as a Web Bot Auth agent whose key directory is
    ``signature_agent`` (an https URL). Returns the fields to append; the
    request itself is not modified. Any header named in ``opts.components``
    must already be on ``req``."""
    opts = opts or SignOptions()
    try:
        agent_url = httpsig.parse_url(signature_agent)
    except ValueError:
        agent_url = None
    if agent_url is None or agent_url.scheme != "https":
        raise _wba_err("signature_agent must be an https URL with a host")
    if not isinstance(opts.validity_secs, int) or not 1 <= opts.validity_secs <= MAX_VALIDITY_SECS:
        raise _wba_err("validity_secs must be between 1 and 86400")
    try:
        if opts.legacy_signature_agent:
            if httpsig.combined_field(req.headers, "signature-agent") is not None:
                raise _wba_err("legacy Signature-Agent cannot be combined with an existing one")
            field_value = httpsig.serialize_sf_item(Item(str(agent_url)))
            agent_component = Component("signature-agent")
        else:
            existing = httpsig.parse_dictionary_field(req.headers, "signature-agent")
            if opts.label in existing:
                raise _wba_err(f"Signature-Agent already has a member '{opts.label}'")
            field_value = httpsig.serialize_sf_dictionary({opts.label: Item(str(agent_url))})
            agent_component = Component.keyed("signature-agent", opts.label)
    except httpsig.StructuredFieldError as e:
        raise _wba_err(f"invalid Signature-Agent or label: {e}") from None
    to_sign = req.header("Signature-Agent", field_value)

    components = [Component("@authority"), agent_component]
    for c in opts.components:
        if c not in components:
            components.append(c)

    created = _now() if opts.created is None else opts.created
    params: List[Param] = [
        ("created", created),
        ("keyid", thumbprint(signing_key.public_key())),
        ("alg", signing_key.alg),
        ("expires", created + opts.validity_secs),
    ]
    if opts.nonce:
        # 64 bytes, as in the draft's vectors; Cloudflare's verifier rejects
        # other lengths.
        params.append(("nonce", base64.b64encode(secrets.token_bytes(64)).decode("ascii")))
    params.append(("tag", TAG))

    fields = httpsig.sign(to_sign, opts.label, components, params, signing_key)
    return SignedHeaders(field_value, fields.signature_input, fields.signature)


# ---------------------------------------------------------------------------
# Verifying requests
# ---------------------------------------------------------------------------


@dataclass
class VerifyOptions:
    """Options for :func:`verify_request`."""

    #: Verification time; ``None`` uses the current time.
    now: Optional[int] = None
    #: Clock skew tolerance in seconds.
    clock_skew_secs: int = 60
    #: Longest accepted ``expires - created`` window.
    max_validity_secs: int = MAX_VALIDITY_SECS
    #: Accept the legacy bare-String ``Signature-Agent`` form (§5.2.1).
    accept_legacy_signature_agent: bool = True
    #: Components every accepted signature must cover, in addition to the
    #: protocol's own requirements.
    required_components: List[Component] = field(default_factory=list)
    #: Replay protection: when set, a verified signature's ``nonce`` is
    #: recorded per keyid until the signature expires, and a repeat is
    #: invalid. Signatures without a nonce are invalid too. Checked only
    #: after the signature verifies, so forged requests cannot fill it.
    nonce_store: Optional[NonceStore] = None


@dataclass
class VerifiedAgent:
    """A request signature that verified against a key its Signature-Agent
    directory provides."""

    label: str
    #: Normalized Signature-Agent URL: the agent's identifier.
    signature_agent: str
    #: JWK thumbprint of the signing key.
    keyid: str
    created: int
    expires: int
    nonce: Optional[str]
    components: List[Component]

    def covers(self, component: Component) -> bool:
        """``True`` if the signature covers ``component``."""
        return component in self.components


@dataclass
class WbaOutcome:
    """One of the three verifier outcomes the draft distinguishes (Appendix C.1).

    - ``verified``: the signature and key material validate (``agent`` is set);
    - ``invalid``: the signature, covered components, key or freshness checks fail;
    - ``unverified``: not enough information to decide (no WBA signature,
      discovery failed, or the resolved directory lacks the key).
    """

    VERIFIED = "verified"
    INVALID = "invalid"
    UNVERIFIED = "unverified"

    status: str
    reason: Optional[str] = None
    agent: Optional[VerifiedAgent] = None

    @classmethod
    def verified_with(cls, agent: VerifiedAgent) -> "WbaOutcome":
        return cls(cls.VERIFIED, None, agent)

    @classmethod
    def invalid_because(cls, reason: str) -> "WbaOutcome":
        return cls(cls.INVALID, reason)

    @classmethod
    def unverified_because(cls, reason: str) -> "WbaOutcome":
        return cls(cls.UNVERIFIED, reason)

    @property
    def verified(self) -> bool:
        return self.status == self.VERIFIED

    @property
    def invalid(self) -> bool:
        return self.status == self.INVALID

    @property
    def unverified(self) -> bool:
        return self.status == self.UNVERIFIED


class KeyLookup(Protocol):
    """Key lookup keyed on the ``(Signature-Agent URL, keyid)`` pair, never on
    the keyid alone (§5.4)."""

    def lookup(self, signature_agent: str, keyid: str) -> Optional[PublicKey]:
        """The key when the directory at ``signature_agent`` provides
        ``keyid``; ``None`` when the directory resolved without it. Raises
        when the directory could not be resolved."""
        ...


def find_key(directory: Directory, keyid: str, now: int, skew: int) -> Optional[PublicKey]:
    """Find ``keyid`` in ``directory`` by computed thumbprint, honoring ``nbf``/``exp``."""
    for jwk in directory.keys:
        if not jwk.usable_at(now, skew):
            continue
        try:
            key = jwk.public_key()
        except AgentPinError:
            continue
        if thumbprint(key) == keyid:
            return key
    return None


class DirectoryKeyStore:
    """In-memory key store built from directories the verifier resolved itself."""

    def __init__(self, clock_skew_secs: int = 60) -> None:
        self._directories: Dict[str, Directory] = {}
        self._lock = threading.Lock()
        self.clock_skew_secs = clock_skew_secs

    def insert(self, signature_agent: str, directory: Directory) -> None:
        """Record (or replace) the directory resolved from ``signature_agent``."""
        key = normalize_signature_agent(signature_agent)
        with self._lock:
            self._directories[key] = directory

    def copy(self) -> "DirectoryKeyStore":
        out = DirectoryKeyStore(self.clock_skew_secs)
        with self._lock:
            out._directories = dict(self._directories)
        return out

    def lookup(self, signature_agent: str, keyid: str) -> Optional[PublicKey]:
        with self._lock:
            d = self._directories.get(signature_agent)
        if d is None:
            raise _wba_err("directory not resolved")
        return find_key(d, keyid, _now(), self.clock_skew_secs)


@dataclass
class _Candidate:
    """A WBA signature that passed every check except the cryptographic one."""

    sig: ParsedSignature
    signature_agent: str
    keyid: str


def _check_signature(req: HttpRequest, sig: ParsedSignature, opts: VerifyOptions, now: int) -> _Candidate:
    """Protocol checks on one signature (§5.2, §5.2.1). Raises ``_Reject``."""
    p = sig.params
    if p.created is None:
        raise _Reject("signature has no created parameter")
    if p.expires is None:
        raise _Reject("signature has no expires parameter")
    if p.keyid is None:
        raise _Reject("signature has no keyid parameter")
    created, expires = p.created, p.expires
    if p.alg is not None and p.alg not in (ALG_ED25519, ALG_RSA_PSS_SHA512):
        raise _Reject(f"unsupported alg '{p.alg}'")
    if created > now + opts.clock_skew_secs:
        raise _Reject("signature created in the future")
    if expires <= created:
        raise _Reject("expires is not after created")
    if now - opts.clock_skew_secs > expires:
        raise _Reject("signature expired")
    if expires - created > opts.max_validity_secs:
        raise _Reject("signature validity window too long")
    if not sig.covers(Component("@authority")) and not sig.covers(Component("@target-uri")):
        raise _Reject("signature covers neither @authority nor @target-uri")
    for c in opts.required_components:
        if not sig.covers(c):
            raise _Reject(f"signature does not cover required '{c.name}'")
    # The covered member, not the signature label, names the agent: labels
    # may be rewritten by intermediaries, member keys may not (§6.6.1).
    members = [c.key for c in sig.components if c.name == "signature-agent" and not c.req and c.key is not None]
    if len(members) == 1:
        signature_agent = _signature_agent_member(req.headers, members[0], False)
    elif not members and opts.accept_legacy_signature_agent and sig.covers(Component("signature-agent")):
        signature_agent = _signature_agent_member(req.headers, sig.label, True)
    elif not members:
        raise _Reject("signature does not cover a Signature-Agent member")
    else:
        raise _Reject("signature covers more than one Signature-Agent member")
    return _Candidate(sig, signature_agent, p.keyid)


def _candidates(req: HttpRequest, opts: VerifyOptions, now: int) -> Tuple[List[_Candidate], Optional[str]]:
    """Parse and check every WBA-tagged signature. Returns candidates and the
    reason for the last invalid one; raises ``_Outcome`` for an early result."""
    try:
        sigs = httpsig.parse_signatures(req.headers)
    except AgentPinError as e:
        raise _Outcome(WbaOutcome.invalid_because(str(e))) from None
    out: List[_Candidate] = []
    invalid: Optional[str] = None
    seen = False
    for sig in sigs:
        if sig.params.tag != TAG:
            continue
        seen = True
        try:
            out.append(_check_signature(req, sig, opts, now))
        except _Reject as e:
            invalid = str(e)
    if not seen:
        raise _Outcome(WbaOutcome.unverified_because("request carries no Web Bot Auth signature"))
    return out, invalid


class _Outcome(Exception):
    def __init__(self, outcome: WbaOutcome) -> None:
        super().__init__(outcome.reason)
        self.outcome = outcome


def _check_nonce(c: _Candidate, opts: VerifyOptions, now: int) -> Optional[str]:
    """Record the nonce of a verified signature; returns the reason it is invalid."""
    store = opts.nonce_store
    if store is None:
        return None
    nonce = c.sig.params.nonce
    if nonce is None:
        return "signature has no nonce and replay protection is on"
    # Keep the nonce until the signature can no longer pass the expiry check.
    expires = c.sig.params.expires if c.sig.params.expires is not None else now
    ttl = max(expires + opts.clock_skew_secs - now, 1)
    try:
        fresh = store.check_and_record(f"{c.keyid} {nonce}", ttl)
    except Exception as e:
        return f"nonce store failed: {e}"
    return None if fresh else "nonce replayed"


def _finish(req: HttpRequest, c: _Candidate, keys: KeyLookup, opts: VerifyOptions, now: int) -> WbaOutcome:
    try:
        key = keys.lookup(c.signature_agent, c.keyid)
    except Exception as e:
        return WbaOutcome.unverified_because(f"key directory {c.signature_agent} unavailable: {e}")
    if key is None:
        return WbaOutcome.unverified_because(f"key directory {c.signature_agent} does not provide keyid {c.keyid}")
    try:
        httpsig.verify(req, c.sig, key)
    except AgentPinError:
        return WbaOutcome.invalid_because("signature verification failed")
    reason = _check_nonce(c, opts, now)
    if reason is not None:
        return WbaOutcome.invalid_because(reason)
    p = c.sig.params
    return WbaOutcome.verified_with(
        VerifiedAgent(
            label=c.sig.label,
            signature_agent=c.signature_agent,
            keyid=c.keyid,
            created=p.created or 0,
            expires=p.expires or 0,
            nonce=p.nonce,
            components=list(c.sig.components),
        )
    )


def verify_request(req: HttpRequest, keys: KeyLookup, opts: Optional[VerifyOptions] = None) -> WbaOutcome:
    """Verify the Web Bot Auth signatures on ``req``. Returns the first
    signature that verifies; otherwise ``invalid`` if any signature failed a
    check, else ``unverified``. Set :attr:`VerifyOptions.nonce_store` to
    reject replays (§5.2.3)."""
    opts = opts or VerifyOptions()
    now = _now() if opts.now is None else opts.now
    try:
        candidates, invalid = _candidates(req, opts, now)
    except _Outcome as o:
        return o.outcome
    result = WbaOutcome.invalid_because(invalid) if invalid is not None else None
    for c in candidates:
        outcome = _finish(req, c, keys, opts, now)
        if outcome.verified:
            return outcome
        # Keep the more decisive of two failures: invalid beats unverified.
        if result is None or not result.invalid:
            result = outcome
    return result or WbaOutcome.unverified_because("no usable signature")


# ---------------------------------------------------------------------------
# Directory responses
# ---------------------------------------------------------------------------


def _directory_request(authority: str) -> HttpRequest:
    return HttpRequest("GET", f"https://{authority}{DIRECTORY_PATH}")


def sign_directory_response(
    body: bytes,
    authority: str,
    keys: Sequence[PrivateKey],
    created: int,
    validity_secs: int,
) -> List[Tuple[str, str]]:
    """Response fields for a signed key directory (Appendix B.1):
    ``Content-Digest`` plus one ``Signature-Input``/``Signature`` per key
    (labels ``binding0``..), each covering ``"@authority";req`` and
    ``content-digest``. ``authority`` is the host (and non-default port) the
    directory was requested on."""
    if not 1 <= validity_secs <= MAX_VALIDITY_SECS:
        raise _wba_err("validity_secs must be between 1 and 86400")
    digest = httpsig.content_digest(body)
    response = HttpResponse(200, [("Content-Digest", digest)], _directory_request(authority))
    components = [Component.of_request("@authority"), Component("content-digest")]
    out = [("Content-Digest", digest)]
    for i, key in enumerate(keys):
        params: List[Param] = [
            ("created", created),
            ("expires", created + validity_secs),
            ("keyid", thumbprint(key.public_key())),
            ("tag", DIRECTORY_TAG),
        ]
        f = httpsig.sign(response, f"binding{i}", components, params, key)
        out.append(("Signature-Input", f.signature_input))
        out.append(("Signature", f.signature))
    return out


def verify_directory_response(
    body: bytes,
    response_headers: Sequence[Tuple[str, str]],
    authority: str,
    now: int,
    clock_skew_secs: int = 60,
) -> Directory:
    """Check a directory response's possession proofs (Appendix B.1) and
    return only the keys that carry a valid one. The ``Content-Digest`` must
    match ``body``; a proof must use the key it names, cover
    ``"@authority";req`` and ``content-digest``, and be neither future-dated
    nor expired."""
    directory = Directory.parse(body)
    if not httpsig.content_digest_matches(response_headers, body):
        raise _wba_err("directory Content-Digest does not match the body")
    response = HttpResponse(200, list(response_headers), _directory_request(authority))
    sigs = httpsig.parse_signatures(response_headers)
    proven = []
    for jwk in directory.keys:
        try:
            pk = jwk.public_key()
        except AgentPinError:
            continue
        tp = thumbprint(pk)
        for s in sigs:
            p = s.params
            if not (
                p.tag == DIRECTORY_TAG
                and p.keyid == tp
                and p.created is not None
                and p.created <= now + clock_skew_secs
                and p.expires is not None
                and now - clock_skew_secs <= p.expires
                and s.covers(Component.of_request("@authority"))
                and s.covers(Component("content-digest"))
            ):
                continue
            try:
                httpsig.verify(response, s, pk)
            except AgentPinError:
                continue
            proven.append(jwk)
            break
    return Directory(proven)


# ---------------------------------------------------------------------------
# AgentPin identity binding (spec §18)
# ---------------------------------------------------------------------------


def request_credential(req: HttpRequest) -> str:
    """The AgentPin credential JWT carried in ``Authorization: AgentPin <jwt>``."""
    auth = httpsig.combined_field(req.headers, "authorization")
    if auth is None:
        raise _wba_err("request has no Authorization field")
    return http_extract_credential(auth)


class BindingFailure(Exception):
    """Why a request's WBA signature and AgentPin credential were not accepted
    together.

    ``kind`` is ``"wba"`` (the signature did not verify; see ``outcome``),
    ``"credential"`` (the credential did not verify; see ``credential``) or
    ``"binding"`` (both verified but are not bound to each other; see
    ``reason``).
    """

    WBA = "wba"
    CREDENTIAL = "credential"
    BINDING = "binding"

    def __init__(
        self,
        kind: str,
        reason: str,
        *,
        outcome: Optional[WbaOutcome] = None,
        credential: Optional[VerificationResult] = None,
    ) -> None:
        super().__init__(reason)
        self.kind = kind
        self.reason = reason
        self.outcome = outcome
        self.credential = credential


def _binding(reason: str) -> BindingFailure:
    return BindingFailure(BindingFailure.BINDING, reason)


def check_binding(
    agent: VerifiedAgent,
    req: HttpRequest,
    credential: VerificationResult,
    discovery: Dict[str, Any],
) -> None:
    """Check that a verified WBA signature and a verified AgentPin credential
    describe the same agent; raises :class:`BindingFailure` (kind ``binding``):

    1. the credential verified, and the signature covers ``authorization``,
       so the credential is bound to this signed request;
    2. the credential's ``cnf.jkt`` equals the signature's ``keyid``;
    3. ``discovery`` is the issuer's document, and it vouches for the
       Signature-Agent URL: listed in ``web_bot_auth.signature_agents``, or,
       when that field is absent, the issuer's well-known directory.
    """
    if not credential.valid:
        raise _binding("AgentPin credential did not verify")
    if not agent.covers(Component("authorization")):
        raise _binding("Web Bot Auth signature does not cover the Authorization field")
    try:
        jwt = request_credential(req)
        _header, payload, _sig = decode_jwt_unverified(jwt)
    except (AgentPinError, ValueError) as e:
        raise _binding(str(e)) from None
    cnf = payload.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if jkt is None:
        raise _binding("credential has no cnf.jkt key confirmation")
    if jkt != agent.keyid:
        raise _binding("credential cnf.jkt does not match the signature keyid")
    try:
        issuer = normalize_domain(payload["iss"])
    except AgentPinError as e:
        raise _binding(str(e)) from None
    try:
        result_issuer: Optional[str] = normalize_domain(credential.issuer) if credential.issuer else None
    except AgentPinError:
        result_issuer = None
    if result_issuer != issuer or credential.agent_id != payload["sub"]:
        raise _binding("credential result does not belong to this request")
    try:
        entity = normalize_domain(discovery.get("entity") if isinstance(discovery, dict) else None)
    except AgentPinError as e:
        raise _binding(str(e)) from None
    if issuer != entity:
        raise _binding("discovery document is not the credential issuer's")
    wba = discovery.get("web_bot_auth")
    if wba is not None:
        agents = wba.get("signature_agents") if isinstance(wba, dict) else None
        allowed = False
        for u in agents if isinstance(agents, list) else []:
            try:
                if isinstance(u, str) and normalize_signature_agent(u) == agent.signature_agent:
                    allowed = True
                    break
            except AgentPinError:
                continue
    else:
        allowed = normalize_signature_agent(well_known_directory(entity)) == agent.signature_agent
    if not allowed:
        raise _binding(f"{entity} does not vouch for Signature-Agent {agent.signature_agent}")


@dataclass
class BoundAgent:
    """A request whose WBA signature and AgentPin credential verified and are
    bound to each other."""

    agent: VerifiedAgent
    credential: VerificationResult


def verify_bound_request(
    req: HttpRequest,
    keys: KeyLookup,
    resolver: Any,
    pin_store: KeyPinStore,
    audience: Optional[str] = None,
    wba_opts: Optional[VerifyOptions] = None,
    config: Optional[VerifierConfig] = None,
) -> BoundAgent:
    """Verify a request's WBA signature, its AgentPin credential, and the
    binding between them (:func:`check_binding`).

    ``resolver`` provides ``resolve_discovery(domain)`` and optionally
    ``resolve_revocation(domain, discovery)`` (for example a
    :class:`~agentpin.resolver_local.LocalAgentCardStore` or a trust-bundle
    lookup). Raises :class:`BindingFailure`.
    """
    from .verification import verify_credential_with_resolver

    outcome = verify_request(req, keys, wba_opts)
    if not outcome.verified or outcome.agent is None:
        raise BindingFailure(BindingFailure.WBA, outcome.reason or "signature did not verify", outcome=outcome)
    agent = outcome.agent
    try:
        jwt = request_credential(req)
    except AgentPinError as e:
        raise _binding(str(e)) from None
    credential = verify_credential_with_resolver(jwt, resolver, pin_store, audience, config)
    if not credential.valid:
        raise BindingFailure(
            BindingFailure.CREDENTIAL,
            credential.error_message or "AgentPin credential did not verify",
            credential=credential,
        )
    try:
        discovery = resolver.resolve_discovery(credential.issuer or "")
    except Exception as e:
        raise _binding(str(e)) from None
    check_binding(agent, req, credential, discovery)
    return BoundAgent(agent, credential)

