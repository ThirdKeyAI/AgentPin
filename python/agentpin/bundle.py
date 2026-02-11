"""Trust bundle support for AgentPin.

A trust bundle is a pre-shared collection of discovery and revocation
documents, enabling verification in environments where the standard
.well-known HTTP discovery is unavailable.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .jwt import decode_jwt_unverified
from .pinning import KeyPinStore
from .types import ErrorCode, VerificationResult, VerifierConfig
from .verification import verify_credential_offline


def create_trust_bundle(created_at: Optional[str] = None) -> Dict[str, Any]:
    """Create a new empty trust bundle."""
    return {
        "agentpin_bundle_version": "0.1",
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "documents": [],
        "revocations": [],
    }


def find_bundle_discovery(bundle: Dict[str, Any], domain: str) -> Optional[Dict[str, Any]]:
    """Find a discovery document in a bundle by domain."""
    for doc in bundle.get("documents", []):
        if doc.get("entity") == domain:
            return doc
    return None


def find_bundle_revocation(bundle: Dict[str, Any], domain: str) -> Optional[Dict[str, Any]]:
    """Find a revocation document in a bundle by domain."""
    for doc in bundle.get("revocations", []):
        if doc.get("entity") == domain:
            return doc
    return None


def load_trust_bundle(path: str) -> Dict[str, Any]:
    """Load a trust bundle from a JSON file."""
    with open(path) as f:
        return json.load(f)


def save_trust_bundle(bundle: Dict[str, Any], path: str) -> None:
    """Save a trust bundle to a JSON file."""
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2)


def verify_credential_with_bundle(
    credential_jwt: str,
    bundle: Dict[str, Any],
    pin_store: KeyPinStore,
    audience: Optional[str] = None,
    config: Optional[VerifierConfig] = None,
) -> VerificationResult:
    """Verify a credential using a trust bundle for discovery.

    Extracts the issuer domain from the JWT, looks up the discovery and
    revocation documents from the bundle, then delegates to
    verify_credential_offline.
    """
    if config is None:
        config = VerifierConfig()

    try:
        _header, payload, _sig = decode_jwt_unverified(credential_jwt)
    except Exception as e:
        return VerificationResult(
            valid=False,
            error_code=ErrorCode.ALGORITHM_REJECTED,
            error_message=f"JWT parse failed: {e}",
        )

    discovery = find_bundle_discovery(bundle, payload["iss"])
    if discovery is None:
        return VerificationResult(
            valid=False,
            error_code=ErrorCode.DISCOVERY_FETCH_FAILED,
            error_message=f"Domain '{payload['iss']}' not found in trust bundle",
        )

    revocation = find_bundle_revocation(bundle, payload["iss"])
    return verify_credential_offline(credential_jwt, discovery, revocation, pin_store, audience, config)
