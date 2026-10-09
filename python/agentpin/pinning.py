"""TOFU (Trust On First Use) key pinning store for AgentPin."""

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .domain import normalize_domain
from .jwk import jwk_thumbprint
from .types import AgentPinError, ErrorCode, TrustLevel


def _pin_key(domain: str) -> str:
    """Pin-store key: the normalized hostname when valid, the raw string otherwise (AP-3)."""
    try:
        return normalize_domain(domain)
    except AgentPinError:
        return str(domain)


class PinningResult:
    FIRST_USE = "first_use"
    MATCHED = "matched"
    CHANGED = "changed"


class KeyPinStore:
    """In-memory TOFU key pinning store."""

    def __init__(self) -> None:
        self.domains: Dict[str, dict] = {}

    def check_and_pin(self, domain: str, jwk: dict) -> str:
        """Check a key against the pin store. TOFU pins on first use.

        Returns:
            One of PinningResult values.
        """
        domain = _pin_key(domain)
        key_hash = jwk_thumbprint(jwk)
        now = datetime.now(timezone.utc).isoformat()

        if domain in self.domains:
            pinned = self.domains[domain]
            for pk in pinned["pinned_keys"]:
                if pk["public_key_hash"] == key_hash:
                    pk["last_seen"] = now
                    return PinningResult.MATCHED
            return PinningResult.CHANGED

        # First time — TOFU pin
        self.domains[domain] = {
            "domain": domain,
            "pinned_keys": [
                {
                    "kid": jwk.get("kid", ""),
                    "public_key_hash": key_hash,
                    "first_seen": now,
                    "last_seen": now,
                    "trust_level": TrustLevel.TOFU,
                }
            ],
        }
        return PinningResult.FIRST_USE

    def add_key(self, domain: str, jwk: dict) -> None:
        """Add a key to an existing domain's pin set (e.g., during key rotation)."""
        domain = _pin_key(domain)
        key_hash = jwk_thumbprint(jwk)
        now = datetime.now(timezone.utc).isoformat()

        if domain not in self.domains:
            self.domains[domain] = {"domain": domain, "pinned_keys": []}

        pinned = self.domains[domain]
        if not any(pk["public_key_hash"] == key_hash for pk in pinned["pinned_keys"]):
            pinned["pinned_keys"].append(
                {
                    "kid": jwk.get("kid", ""),
                    "public_key_hash": key_hash,
                    "first_seen": now,
                    "last_seen": now,
                    "trust_level": TrustLevel.TOFU,
                }
            )

    def get_domain(self, domain: str) -> Optional[dict]:
        """Get pinned domain info."""
        return self.domains.get(_pin_key(domain))

    def to_json(self) -> str:
        """Serialize the store to JSON."""
        return json.dumps(list(self.domains.values()), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "KeyPinStore":
        """Deserialize the store from JSON."""
        store = cls()
        domains: List[dict] = json.loads(json_str)
        for d in domains:
            key = _pin_key(d["domain"])
            existing = store.domains.get(key)
            if existing is None:
                entry = dict(d)
                entry["domain"] = key
                entry["pinned_keys"] = list(d.get("pinned_keys", []))
                store.domains[key] = entry
                continue
            # Merge entries that differ only by case into one pin set.
            for pk in d.get("pinned_keys", []):
                if not any(e.get("public_key_hash") == pk.get("public_key_hash") for e in existing["pinned_keys"]):
                    existing["pinned_keys"].append(pk)
        return store


def check_pinning(store: KeyPinStore, domain: str, jwk: dict) -> str:
    """Check pinning and raise an error if key has changed.

    Returns:
        PinningResult value.

    Raises:
        AgentPinError: if key has changed since last pinned.
    """
    result = store.check_and_pin(domain, jwk)
    if result == PinningResult.CHANGED:
        raise AgentPinError(
            ErrorCode.KEY_PIN_MISMATCH,
            f"Key for domain '{domain}' has changed since last pinned (kid: '{jwk.get('kid', '')}')",
        )
    return result
