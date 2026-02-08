"""ES256-only JWT encode/decode/verify for AgentPin."""

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePrivateKey, EllipticCurvePublicKey

REQUIRED_ALG = "ES256"
REQUIRED_TYP = "agentpin-credential+jwt"


def base64url_encode(data: bytes) -> str:
    """Base64url encode bytes (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def base64url_decode(s: str) -> bytes:
    """Base64url decode a string."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


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

    if header.get("alg") != REQUIRED_ALG:
        raise ValueError(f"Algorithm '{header.get('alg')}' rejected, must be '{REQUIRED_ALG}'")

    if header.get("typ") != REQUIRED_TYP:
        raise ValueError(f"Token type '{header.get('typ')}' rejected, must be '{REQUIRED_TYP}'")

    return header, payload, parts[2]


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
