"""ES256-only JWT encode/decode/verify for AgentPin."""

import base64
import json
import re

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey

REQUIRED_ALG = "ES256"
REQUIRED_TYP = "agentpin-credential+jwt"


def base64url_encode(data: bytes) -> str:
    """Base64url encode bytes (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def base64url_decode(s: str) -> bytes:
    """Base64url decode a string strictly.

    RFC 7515 §2 / RFC 4648 §5 without padding: only the base64url alphabet,
    no padding, no whitespace, and canonical trailing bits. Non-canonical
    input raises ``ValueError`` rather than being silently accepted, so every
    SDK agrees on which tokens are well formed.
    """
    if not isinstance(s, str) or not _BASE64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("Invalid base64url encoding")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64url_encode(raw) != s:
        raise ValueError("Non-canonical base64url encoding")
    return raw


def encode_jwt(header: dict, payload: dict, private_key_pem: str) -> str:
    """Encode a JWT from header + payload + PEM private key."""
    header_json = json.dumps(header, separators=(",", ":"))
    payload_json = json.dumps(payload, separators=(",", ":"))

    header_b64 = base64url_encode(header_json.encode("utf-8"))
    payload_b64 = base64url_encode(payload_json.encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}"

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey)
    signature = private_key.sign(signing_input.encode("utf-8"), ECDSA(hashes.SHA256()))
    sig_b64 = base64url_encode(signature)

    return f"{signing_input}.{sig_b64}"


def decode_jwt_unverified(jwt_str: str) -> tuple:
    """Decode a JWT without verifying the signature.

    Returns:
        Tuple of (header: dict, payload: dict, signature_b64: str)

    Raises:
        ValueError: if JWT is malformed, wrong algorithm, or wrong type
    """
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have 3 parts")

    header = json.loads(base64url_decode(parts[0]))
    payload = json.loads(base64url_decode(parts[1]))

    if not isinstance(header, dict):
        raise ValueError("JWT header is not a JSON object")
    if header.get("alg") != REQUIRED_ALG:
        raise ValueError(f"Algorithm '{header.get('alg')}' rejected, must be '{REQUIRED_ALG}'")

    if header.get("typ") != REQUIRED_TYP:
        raise ValueError(f"Token type '{header.get('typ')}' rejected, must be '{REQUIRED_TYP}'")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise MalformedCredentialError("kid is missing")

    # Payload shape: a JSON object whose claims have the right types;
    # anything else is a malformed credential (AP-5, AP-18).
    validate_claims(payload)

    return header, payload, parts[2]


CREDENTIAL_VERSION = "0.1"
"""Protocol version a credential's ``agentpin_version`` claim must carry."""


class MalformedCredentialError(ValueError):
    """A JWT whose claims are missing, mistyped or inconsistent (AP-5, AP-14, AP-18).

    Verifiers map it to ``MALFORMED_CREDENTIAL``.
    """

    def __init__(self, reason: str):
        super().__init__(f"Malformed credential: {reason}")
        self.reason = reason


def _is_nonneg_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_claims(payload: object) -> None:
    """Validate the shape of a credential payload.

    Required string identifiers, non-negative integer timestamps with
    ``exp > iat``, a capability list of strings, a supported protocol version,
    and correctly typed optional claims.

    Raises:
        MalformedCredentialError
    """
    if not isinstance(payload, dict):
        raise MalformedCredentialError("JWT payload is not a JSON object")
    for claim in ("iss", "sub", "jti"):
        if not isinstance(payload.get(claim), str) or not payload.get(claim):
            raise MalformedCredentialError(f"{claim} is missing or not a non-empty string")
    if not _is_nonneg_int(payload.get("iat")):
        raise MalformedCredentialError("iat is missing or not a non-negative integer")
    if not _is_nonneg_int(payload.get("exp")):
        raise MalformedCredentialError("exp is missing or not a non-negative integer")
    if payload["exp"] <= payload["iat"]:
        raise MalformedCredentialError("exp must be greater than iat")
    if payload.get("nbf") is not None and not _is_nonneg_int(payload.get("nbf")):
        raise MalformedCredentialError("nbf is not a non-negative integer")
    if payload.get("agentpin_version") != CREDENTIAL_VERSION:
        raise MalformedCredentialError(f"Unsupported agentpin_version '{payload.get('agentpin_version')}'")
    caps = payload.get("capabilities")
    if not isinstance(caps, list) or not all(isinstance(c, str) for c in caps):
        raise MalformedCredentialError("capabilities must be an array of strings")
    if payload.get("aud") is not None and not isinstance(payload.get("aud"), str):
        raise MalformedCredentialError("aud must be a string")
    if payload.get("nonce") is not None and not isinstance(payload.get("nonce"), str):
        raise MalformedCredentialError("nonce must be a string")
    if payload.get("constraints") is not None and not isinstance(payload.get("constraints"), dict):
        raise MalformedCredentialError("constraints must be an object")
    chain = payload.get("delegation_chain")
    if chain is not None:
        if not isinstance(chain, list):
            raise MalformedCredentialError("delegation_chain must be an array")
        for att in chain:
            if not isinstance(att, dict):
                raise MalformedCredentialError("delegation_chain entries must be objects")
            for field in ("domain", "role", "agent_id", "kid", "attestation"):
                if not isinstance(att.get(field), str) or not att.get(field):
                    raise MalformedCredentialError(f"delegation_chain entry {field} is missing")
            if att.get("exp") is not None and not _is_nonneg_int(att.get("exp")):
                raise MalformedCredentialError("delegation_chain entry exp is not a non-negative integer")


def verify_jwt(jwt_str: str, public_key_pem: str) -> tuple:
    """Verify a JWT signature using a PEM public key.

    Returns:
        Tuple of (header: dict, payload: dict)

    Raises:
        ValueError: if JWT is invalid or signature verification fails
    """
    header, payload, _sig_b64 = decode_jwt_unverified(jwt_str)

    parts = jwt_str.split(".")
    signing_input = f"{parts[0]}.{parts[1]}"
    sig_bytes = base64url_decode(parts[2])

    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    assert isinstance(public_key, EllipticCurvePublicKey)

    try:
        public_key.verify(sig_bytes, signing_input.encode("utf-8"), ECDSA(hashes.SHA256()))
    except Exception as e:
        raise ValueError(f"JWT signature verification failed: {e}") from e

    return header, payload
