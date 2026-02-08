"""Mutual authentication challenge-response protocol for AgentPin."""

import base64
import os
from datetime import datetime, timezone
from typing import Optional

from .crypto import sign_data, verify_signature

NONCE_EXPIRY_SECS = 60


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def create_challenge(verifier_credential: Optional[str] = None) -> dict:
    """Create a challenge with a 128-bit random nonce."""
    nonce_bytes = os.urandom(16)  # 128 bits
    nonce = _base64url_encode(nonce_bytes)

    challenge: dict = {
        "type": "agentpin-challenge",
        "nonce": nonce,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if verifier_credential:
        challenge["verifier_credential"] = verifier_credential

    return challenge


def create_response(challenge: dict, private_key_pem: str, kid: str) -> dict:
    """Create a response by signing the challenge nonce."""
    signature = sign_data(private_key_pem, challenge["nonce"].encode("utf-8"))

    return {
        "type": "agentpin-response",
        "nonce": challenge["nonce"],
        "signature": signature,
        "kid": kid,
    }


def verify_response(response: dict, challenge: dict, public_key_pem: str) -> bool:
    """Verify a challenge response: check signature and that nonce hasn't expired.

    Raises:
        ValueError: if nonce has expired.
    """
    # Check nonce matches
    if response["nonce"] != challenge["nonce"]:
        return False

    # Check timestamp hasn't expired
    ts = datetime.fromisoformat(challenge["timestamp"])
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    elapsed = (datetime.now(timezone.utc) - ts).total_seconds()
    if elapsed > NONCE_EXPIRY_SECS:
        raise ValueError(f"Challenge nonce expired ({int(elapsed)} seconds old, max {NONCE_EXPIRY_SECS})")

    # Verify signature over the nonce
    return verify_signature(public_key_pem, challenge["nonce"].encode("utf-8"), response["signature"])
