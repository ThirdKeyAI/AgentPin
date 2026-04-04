"""Key rotation helpers for AgentPin."""

from datetime import datetime, timezone

from .crypto import generate_key_id, generate_key_pair
from .jwk import pem_to_jwk
from .revocation import add_revoked_key


def prepare_rotation(old_kid: str) -> dict:
    """Prepare a key rotation: generate new keypair, compute kid and JWK.

    Returns dict with keys: new_key_pair, new_kid, new_jwk, old_kid
    """
    private_pem, public_pem = generate_key_pair()
    new_kid = generate_key_id(public_pem)
    new_jwk = pem_to_jwk(public_pem, new_kid)
    return {
        "new_key_pair": (private_pem, public_pem),
        "new_kid": new_kid,
        "new_jwk": new_jwk,
        "old_kid": old_kid,
    }


def apply_rotation(doc: dict, plan: dict) -> None:
    """Apply rotation plan: add new key to discovery document."""
    doc["public_keys"].append(plan["new_jwk"])
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()


def complete_rotation(
    doc: dict, revocation_doc: dict, old_kid: str, reason: str
) -> None:
    """Complete rotation: remove old key from discovery, add to revocation."""
    doc["public_keys"] = [
        k for k in doc["public_keys"] if k.get("kid") != old_kid
    ]
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()
    add_revoked_key(revocation_doc, old_kid, reason)
