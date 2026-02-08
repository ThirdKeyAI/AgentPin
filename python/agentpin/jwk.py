"""JWK (JSON Web Key) operations for AgentPin."""

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicKey,
    EllipticCurvePublicNumbers,
)

from .crypto import sha256_hex


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def pem_to_jwk(public_key_pem: str, kid: str) -> dict:
    """Convert a PEM public key to a JWK dict."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    assert isinstance(public_key, EllipticCurvePublicKey)
    numbers = public_key.public_numbers()

    x_bytes = numbers.x.to_bytes(32, byteorder="big")
    y_bytes = numbers.y.to_bytes(32, byteorder="big")

    return {
        "kid": kid,
        "kty": "EC",
        "crv": "P-256",
        "x": _base64url_encode(x_bytes),
        "y": _base64url_encode(y_bytes),
        "use": "sig",
        "key_ops": ["verify"],
    }


def jwk_to_pem(jwk: dict) -> str:
    """Convert a JWK dict to a PEM public key string."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("Invalid JWK: must be EC P-256")

    x_bytes = _base64url_decode(jwk["x"])
    y_bytes = _base64url_decode(jwk["y"])

    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("Invalid JWK: x and y must be 32 bytes each")

    x_int = int.from_bytes(x_bytes, byteorder="big")
    y_int = int.from_bytes(y_bytes, byteorder="big")

    public_numbers = EllipticCurvePublicNumbers(x_int, y_int, SECP256R1())
    public_key = public_numbers.public_key()

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def jwk_thumbprint(jwk: dict) -> str:
    """Compute JWK thumbprint per RFC 7638.

    SHA-256 of canonical JSON with alphabetically sorted required members: crv, kty, x, y.
    """
    canonical = f'{{"crv":"{jwk["crv"]}","kty":"{jwk["kty"]}","x":"{jwk["x"]}","y":"{jwk["y"]}"}}'
    return sha256_hex(canonical.encode("utf-8"))
