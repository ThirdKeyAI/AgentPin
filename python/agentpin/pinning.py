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
    # Not pinned, but published next to an already-pinned key: pinned as a rotation (spec §7.2).
    ROTATED = "rotated"


class KeyPinStore:
    """In-memory TOFU key pinning store."""

    def __init__(self) -> None:
        self.domains: Dict[str, dict] = {}

    def check_and_pin(self, domain: str, jwk: dict) -> str:
        """Check a single key against the pin store. TOFU pins on first use.

        Prefer :meth:`check_and_pin_set` when the full validated discovery
        document is available.

        Returns:
            One of PinningResult values.
        """
        return self.check_and_pin_set(domain, jwk, [jwk])

    def check_and_pin_set(self, domain: str, jwk: dict, document_keys: List[dict]) -> str:
        """Check ``jwk`` using the key set of a validated discovery document.

        - First use: every key in ``document_keys`` (plus ``jwk``) is pinned.
        - Known domain, ``jwk`` pinned: MATCHED.
        - Known domain, ``jwk`` not pinned, but another key in ``document_keys``
          is already pinned: ``jwk`` is pinned and ROTATED is returned
          (rotation continuity, spec §7.2).
        - Otherwise CHANGED; nothing is modified.
        """
        domain = _pin_key(domain)
        key_hash = jwk_thumbprint(jwk)
        now = datetime.now(timezone.utc).isoformat()

        pinned = self.domains.get(domain)
        if pinned is None:
            self.domains[domain] = {"domain": domain, "pinned_keys": []}
            self.add_key(domain, jwk)
            for k in document_keys or []:
                self.add_key(domain, k)
            return PinningResult.FIRST_USE

        for pk in pinned["pinned_keys"]:
            if pk["public_key_hash"] == key_hash:
                pk["last_seen"] = now
                return PinningResult.MATCHED

        pinned_hashes = {pk["public_key_hash"] for pk in pinned["pinned_keys"]}
        for k in document_keys or []:
            h = jwk_thumbprint(k)
            if h != key_hash and h in pinned_hashes:
                self.add_key(domain, jwk)
                return PinningResult.ROTATED
        return PinningResult.CHANGED

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
    return check_pinning_set(store, domain, jwk, [jwk])


def check_pinning_set(store: KeyPinStore, domain: str, jwk: dict, document_keys: List[dict]) -> str:
    """check_pinning over a validated document's key set; see KeyPinStore.check_and_pin_set."""
    result = store.check_and_pin_set(domain, jwk, document_keys)
    if result == PinningResult.CHANGED:
        raise AgentPinError(
            ErrorCode.KEY_PIN_MISMATCH,
            f"Key for domain '{domain}' has changed since last pinned (kid: '{jwk.get('kid', '')}')",
        )
    return result
