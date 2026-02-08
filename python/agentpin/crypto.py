"""ECDSA P-256 cryptographic operations for AgentPin."""

import base64
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)


def generate_key_pair() -> tuple:
    """Generate a new ECDSA P-256 keypair.

    Returns:
        Tuple of (private_key_pem: str, public_key_pem: str)
    """
    private_key = ec.generate_private_key(SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_key_pem, public_key_pem


def sign_data(private_key_pem: str, data: bytes) -> str:
    """Sign data with a PEM-encoded private key. Returns base64-encoded DER signature."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    assert isinstance(private_key, EllipticCurvePrivateKey)
    signature = private_key.sign(data, ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key_pem: str, data: bytes, signature_b64: str) -> bool:
    """Verify a base64-encoded DER signature against data using a PEM public key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        assert isinstance(public_key, EllipticCurvePublicKey)
        sig_bytes = base64.b64decode(signature_b64)
        public_key.verify(sig_bytes, data, ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def generate_key_id(public_key_pem: str) -> str:
    """Generate a key ID: SHA-256 of DER-encoded SPKI, hex-encoded."""
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_hex(der_bytes)


def sha256_hash(data: bytes) -> bytes:
    """SHA-256 hash of arbitrary data."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """SHA-256 hash, hex-encoded."""
    return hashlib.sha256(data).hexdigest()
