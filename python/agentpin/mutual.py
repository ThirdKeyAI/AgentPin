"""Mutual authentication challenge-response protocol for AgentPin (spec §9).

The responder signs a domain-separated structure, never the raw nonce::

    "agentpin-response-v1" 0x00 len(nonce) nonce len(timestamp) timestamp
                                len(kid) kid len(binding) binding

where ``binding`` is the SHA-256 (hex) of the challenge's
``verifier_credential`` when present (empty otherwise). This binds a response
to this verifier and this challenge only, and keeps the signature disjoint
from credential, attestation and AgentCard signatures (AP-1, design 8).

Nonces are single-use by default: verification always goes through a nonce
store (a module-wide :class:`InMemoryNonceStore` unless the caller supplies
one) and the nonce is recorded only after the signature verified, so a forged
response cannot burn a legitimate nonce (AP-19).
"""

import base64
import os
import re
from datetime import datetime, timezone
from typing import Optional

from .crypto import CTX_RESPONSE, domain_separated_input, sha256_hex, sign_data, verify_signature
from .nonce import InMemoryNonceStore, NonceStore

NONCE_EXPIRY_SECS = 60
NONCE_BYTES = 16
NONCE_ENCODED_LEN = 22
CHALLENGE_TYPE = "agentpin-challenge"
RESPONSE_TYPE = "agentpin-response"

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_default_nonce_store = InMemoryNonceStore()


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def create_challenge(verifier_credential: Optional[str] = None) -> dict:
    """Create a challenge with a 128-bit random nonce."""
    nonce_bytes = os.urandom(NONCE_BYTES)
    nonce = _base64url_encode(nonce_bytes)

    challenge: dict = {
        "type": CHALLENGE_TYPE,
        "nonce": nonce,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if verifier_credential:
        challenge["verifier_credential"] = verifier_credential

    return challenge


def validate_nonce(nonce: object) -> None:
    """Require exactly 22 canonical base64url characters decoding to 16 bytes.

    Raises ValueError otherwise, so a responder is never asked to sign
    caller-shaped bytes.
    """
    if not isinstance(nonce, str) or len(nonce) != NONCE_ENCODED_LEN:
        raise ValueError(f"Challenge nonce must be {NONCE_ENCODED_LEN} base64url characters")
    if not _B64URL_RE.match(nonce):
        raise ValueError("Challenge nonce is not valid base64url")
    raw = base64.urlsafe_b64decode(nonce + "==")
    if len(raw) != NONCE_BYTES or _base64url_encode(raw) != nonce:
        raise ValueError(f"Challenge nonce must decode to exactly {NONCE_BYTES} bytes")


def verifier_binding(challenge: dict) -> str:
    """SHA-256 hex of the challenge's verifier credential, or '' when absent."""
    cred = challenge.get("verifier_credential")
    return sha256_hex(str(cred).encode("utf-8")) if cred else ""


def response_signing_input(challenge: dict, kid: str) -> bytes:
    """The bytes a responder with key ``kid`` commits to for ``challenge``."""
    return domain_separated_input(
        CTX_RESPONSE,
        [
            str(challenge["nonce"]),
            str(challenge["timestamp"]),
            str(kid),
            verifier_binding(challenge),
        ],
    )


def create_response(challenge: dict, private_key_pem: str, kid: str) -> dict:
    """Create a response by signing the domain-separated challenge structure.

    Raises ValueError when the challenge nonce is malformed or the type is wrong.
    """
    if challenge.get("type") != CHALLENGE_TYPE:
        raise ValueError(f"Challenge type rejected, must be '{CHALLENGE_TYPE}'")
    validate_nonce(challenge.get("nonce"))
    signature = sign_data(private_key_pem, response_signing_input(challenge, kid))

    return {
        "type": RESPONSE_TYPE,
        "nonce": challenge["nonce"],
        "signature": signature,
        "kid": kid,
    }


def verify_response(response: dict, challenge: dict, public_key_pem: str) -> bool:
    """Verify a challenge response using the module-wide nonce store.

    Each nonce is accepted at most once per process.

    Raises:
        ValueError: if the challenge is malformed, expired, or the nonce was replayed.
    """
    return verify_response_with_nonce_store(response, challenge, public_key_pem, None)


def verify_response_with_nonce_store(
    response: dict, challenge: dict, public_key_pem: str, nonce_store: Optional[NonceStore] = None
) -> bool:
    """Verify a challenge response.

    Order of checks: nonce/type shape, challenge freshness, signature, then
    single-use recording in ``nonce_store`` (the module-wide store when
    ``None``). Returns ``False`` when the nonce does not match or the signature
    does not verify; raises ``ValueError`` for malformed input, expired
    challenges and replayed nonces.
    """
    if not isinstance(response, dict) or not isinstance(challenge, dict):
        return False
    if response.get("type") != RESPONSE_TYPE or challenge.get("type") != CHALLENGE_TYPE:
        return False
    if response.get("nonce") != challenge.get("nonce"):
        return False
    validate_nonce(challenge.get("nonce"))

    # An unparsable timestamp is treated as expired (fail closed).
    try:
        ts = datetime.fromisoformat(str(challenge.get("timestamp")).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise ValueError("Challenge timestamp is not a valid ISO 8601 datetime") from None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
    if elapsed > NONCE_EXPIRY_SECS:
        raise ValueError(f"Challenge nonce expired ({int(elapsed)} seconds old, max {NONCE_EXPIRY_SECS})")

    # Verify the signature before touching the nonce store so a forged
    # response cannot consume a legitimate nonce.
    input_bytes = response_signing_input(challenge, str(response.get("kid", "")))
    if not verify_signature(public_key_pem, input_bytes, str(response.get("signature", ""))):
        return False

    store = nonce_store if nonce_store is not None else _default_nonce_store
    if not store.check_and_record(response["nonce"], NONCE_EXPIRY_SECS):
        raise ValueError("Nonce has already been used")
    return True
