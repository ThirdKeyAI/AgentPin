"""Trust bundle support for AgentPin.

A trust bundle is a pre-shared collection of discovery and revocation
documents, enabling verification in environments where the standard
.well-known HTTP discovery is unavailable.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .crypto import CTX_BUNDLE, domain_separated_input, sign_data, verify_signature
from .domain import normalize_domain
from .jwt import decode_jwt_unverified
from .pinning import KeyPinStore
from .types import AgentPinError, ErrorCode, VerificationResult, VerifierConfig
from .verification import verify_credential_offline


def _bundle_key(entity: object) -> str:
    try:
        return normalize_domain(entity)
    except AgentPinError:
        return str(entity)


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
    key = _bundle_key(domain)
    for doc in bundle.get("documents", []):
        if _bundle_key(doc.get("entity")) == key:
            return doc
    return None


def find_bundle_revocation(bundle: Dict[str, Any], domain: str) -> Optional[Dict[str, Any]]:
    """Find a revocation document in a bundle by domain."""
    key = _bundle_key(domain)
    for doc in bundle.get("revocations", []):
        if _bundle_key(doc.get("entity")) == key:
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

    class _BundleResolver:
        def resolve_discovery(self, domain: str) -> Dict[str, Any]:
            doc = find_bundle_discovery(bundle, domain)
            if doc is None:
                raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"Domain '{domain}' not found in trust bundle")
            return doc

    return verify_credential_offline(
        credential_jwt, discovery, revocation, pin_store, audience, config, chain_resolver=_BundleResolver()
    )


# ---------------------------------------------------------------------------
# Signed trust bundles (design issue 5)
# ---------------------------------------------------------------------------


def bundle_signing_input(bundle: Dict[str, Any]) -> bytes:
    """The ``agentpin-bundle-v1`` context over the canonical JSON of the bundle
    with ``signature`` cleared."""
    from .a2a import canonicalize_for_signing

    rest = {k: v for k, v in bundle.items() if k != "signature"}
    return domain_separated_input(CTX_BUNDLE, [canonicalize_for_signing(rest).encode("utf-8")])


def sign_trust_bundle(bundle: Dict[str, Any], private_key_pem: str, kid: str) -> Dict[str, Any]:
    """Sign a trust bundle in place with the operator key identified by ``kid``."""
    bundle["kid"] = kid
    bundle.pop("signature", None)
    bundle["signature"] = sign_data(private_key_pem, bundle_signing_input(bundle))
    return bundle


def check_bundle_expiry(bundle: Dict[str, Any]) -> None:
    """Reject a bundle whose ``expires_at`` is unparsable or in the past."""
    raw = bundle.get("expires_at")
    if raw is None:
        return
    try:
        exp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Trust bundle expires_at is not RFC 3339") from None
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Trust bundle has expired")


def verify_trust_bundle(bundle: Dict[str, Any], public_key_pem: str) -> None:
    """Verify a bundle's signature under ``public_key_pem`` and reject it when
    expired. Unsigned bundles are rejected."""
    if bundle.get("signature") is None:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Trust bundle is not signed")
    if not verify_signature(public_key_pem, bundle_signing_input(bundle), str(bundle.get("signature"))):
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "Trust bundle signature did not verify")
    check_bundle_expiry(bundle)
