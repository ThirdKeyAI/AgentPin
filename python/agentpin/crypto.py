"""ECDSA P-256 cryptographic operations for AgentPin."""

import base64
import hashlib
import struct
from typing import Sequence, Union

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


# ---------------------------------------------------------------------------
# Domain-separated signing (protocol v0.4)
# ---------------------------------------------------------------------------
#
# Every object AgentPin signs other than the credential JWT goes through
# domain_separated_input, which prefixes a fixed context label and
# length-prefixes each field. The JWT keeps the RFC 7515 "header.payload"
# signing input, whose alphabet (base64url plus '.') never contains the NUL
# byte that terminates every context label, so no signature produced for one
# object type can be replayed as another.

CTX_RESPONSE = "agentpin-response-v1"
"""Context label for challenge responses."""
CTX_ATTESTATION = "agentpin-attestation-v1"
"""Context label for delegation attestations."""
CTX_AGENTCARD = "agentpin-agentcard-v1"
"""Context label for A2A AgentCard signatures."""
CTX_REVOCATION = "agentpin-revocation-v1"
"""Context label for signed revocation documents."""
CTX_BUNDLE = "agentpin-bundle-v1"
"""Context label for signed trust bundles."""


def domain_separated_input(context: str, fields: Sequence[Union[bytes, str]]) -> bytes:
    """Build the signing input ``context || 0x00 || (u32_be(len) || field)*``.

    Byte-identical to the Rust, Go and JavaScript SDKs.
    """
    out = bytearray(context.encode("utf-8"))
    out.append(0)
    for field in fields:
        raw = field.encode("utf-8") if isinstance(field, str) else bytes(field)
        out.extend(struct.pack(">I", len(raw)))
        out.extend(raw)
    return bytes(out)


def sign_with_context(private_key_pem: str, context: str, fields: Sequence[Union[bytes, str]]) -> str:
    """Sign ``fields`` under ``context``. Returns the standard-base64 DER signature."""
    return sign_data(private_key_pem, domain_separated_input(context, fields))


def verify_with_context(
    public_key_pem: str, context: str, fields: Sequence[Union[bytes, str]], signature_b64: str
) -> bool:
    """Verify a signature produced by :func:`sign_with_context`."""
    return verify_signature(public_key_pem, domain_separated_input(context, fields), signature_b64)


def sign_data(private_key_pem: str, data: bytes) -> str:
    """Sign data with a PEM-encoded private key. Returns base64-encoded DER signature.

    This is a low-level primitive. Protocol objects MUST be signed through
    :func:`sign_with_context` (or the JWT encoder) so signatures over different
    object types can never be confused; never pass caller-supplied bytes here.
    """
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
