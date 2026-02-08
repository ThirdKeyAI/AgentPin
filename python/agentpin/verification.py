"""Credential verification for AgentPin.

Implements the 12-step verification flow from the spec.
"""

import math
import time
from datetime import datetime, timezone
from typing import Optional

from .constraint import constraints_subset_of
from .credential import validate_credential_against_discovery
from .discovery import fetch_discovery_document, find_agent_by_id, find_key_by_kid, validate_discovery_document
from .jwk import jwk_to_pem
from .jwt import decode_jwt_unverified, verify_jwt
from .pinning import KeyPinStore, PinningResult, check_pinning
from .revocation import check_revocation, fetch_revocation_document
from .types import AgentPinError, ErrorCode, VerificationResult, VerifierConfig


def _success(
    agent_id: str,
    issuer: str,
    capabilities: list,
    constraints: Optional[dict],
    pin_status: dict,
) -> VerificationResult:
    return VerificationResult(
        valid=True,
        agent_id=agent_id,
        issuer=issuer,
        capabilities=capabilities,
        constraints=constraints,
        key_pinning=pin_status,
    )


def _failure(code: str, message: str) -> VerificationResult:
    return VerificationResult(valid=False, error_code=code, error_message=message)


def verify_credential_offline(
    credential_jwt: str,
    discovery: dict,
    revocation: Optional[dict],
    pin_store: KeyPinStore,
    audience: Optional[str],
    config: Optional[VerifierConfig] = None,
) -> VerificationResult:
    """Verify a credential offline using caller-provided documents.

    Implements the 12-step verification flow from the spec.
    """
    if config is None:
        config = VerifierConfig()

    # Step 1: Parse JWT
    try:
        header, payload, _sig = decode_jwt_unverified(credential_jwt)
    except Exception as e:
        return _failure(ErrorCode.ALGORITHM_REJECTED, f"JWT parse failed: {e}")

    # Step 2: Check temporal validity
    now = math.floor(time.time())
    skew = config.clock_skew_secs

    if payload.get("iat", 0) > now + skew:
        return _failure(ErrorCode.CREDENTIAL_EXPIRED, "Credential issued in the future")
    if payload.get("exp", 0) <= now - skew:
        return _failure(ErrorCode.CREDENTIAL_EXPIRED, "Credential has expired")
    nbf = payload.get("nbf")
    if nbf is not None and nbf > now + skew:
        return _failure(ErrorCode.CREDENTIAL_EXPIRED, "Credential not yet valid (nbf)")

    lifetime = payload.get("exp", 0) - payload.get("iat", 0)
    if lifetime > config.max_ttl_secs:
        return _failure(
            ErrorCode.CREDENTIAL_EXPIRED,
            f"Credential lifetime {lifetime} exceeds max TTL {config.max_ttl_secs}",
        )

    # Step 3: Validate discovery document
    try:
        validate_discovery_document(discovery, payload["iss"])
    except AgentPinError as e:
        return _failure(ErrorCode.DISCOVERY_INVALID, f"Discovery validation failed: {e}")

    # Step 4: Resolve public key by kid
    jwk = find_key_by_kid(discovery, header["kid"])
    if not jwk:
        return _failure(ErrorCode.KEY_NOT_FOUND, f"Key '{header['kid']}' not found in discovery document")

    # Check key expiration
    if jwk.get("exp"):
        try:
            exp_dt = datetime.fromisoformat(jwk["exp"])
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt.timestamp() < now - skew:
                return _failure(ErrorCode.KEY_EXPIRED, f"Key '{header['kid']}' has expired")
        except (ValueError, TypeError):
            pass

    # Convert JWK to PEM
    try:
        public_key_pem = jwk_to_pem(jwk)
    except Exception as e:
        return _failure(ErrorCode.KEY_NOT_FOUND, f"Invalid key format for '{header['kid']}': {e}")

    # Step 5: Verify JWT signature
    try:
        verify_jwt(credential_jwt, public_key_pem)
    except Exception:
        return _failure(ErrorCode.SIGNATURE_INVALID, f"JWT signature verification failed for kid '{header['kid']}'")

    # Step 6: Check revocation
    if revocation:
        try:
            check_revocation(revocation, payload["jti"], payload["sub"], header["kid"])
        except AgentPinError as e:
            return _failure(e.code, str(e))

    # Step 7: Validate agent status
    agent = find_agent_by_id(discovery, payload["sub"])
    if not agent:
        return _failure(ErrorCode.AGENT_NOT_FOUND, f"Agent '{payload['sub']}' not found in discovery document")
    if agent.get("status") != "active":
        return _failure(ErrorCode.AGENT_INACTIVE, f"Agent '{payload['sub']}' status is {agent.get('status')}")

    # Step 8: Validate capabilities
    try:
        validate_credential_against_discovery(payload.get("capabilities", []), agent.get("capabilities", []))
    except AgentPinError as e:
        return _failure(ErrorCode.CAPABILITY_EXCEEDED, str(e))

    # Step 9: Validate constraints
    if not constraints_subset_of(agent.get("constraints"), payload.get("constraints")):
        return _failure(
            ErrorCode.CONSTRAINT_VIOLATION,
            "Credential constraints are less restrictive than discovery defaults",
        )

    # Step 10: Delegation chain (offline: note only)
    result = _success(
        payload["sub"],
        payload["iss"],
        payload.get("capabilities", []),
        payload.get("constraints"),
        {"status": "unknown", "first_seen": None},
    )

    if payload.get("delegation_chain"):
        entries = [
            {"domain": att["domain"], "role": att["role"], "verified": False}
            for att in payload["delegation_chain"]
        ]
        result.delegation_chain = entries
        result.delegation_verified = False
        result.warnings.append("Delegation chain present but not verified in offline mode")

    # Step 11: TOFU key pinning
    try:
        pin_result = check_pinning(pin_store, payload["iss"], jwk)
        if pin_result == PinningResult.FIRST_USE:
            result.key_pinning = {"status": "first_use", "first_seen": datetime.now(timezone.utc).isoformat()}
        elif pin_result == PinningResult.MATCHED:
            domain_data = pin_store.get_domain(payload["iss"])
            first_seen = None
            if domain_data and domain_data.get("pinned_keys"):
                first_seen = domain_data["pinned_keys"][0].get("first_seen")
            result.key_pinning = {"status": "pinned", "first_seen": first_seen}
    except AgentPinError:
        return _failure(ErrorCode.KEY_PIN_MISMATCH, f"Key for '{payload['iss']}' has changed since last pinned")

    # Step 12: Check audience
    if audience and payload.get("aud"):
        cred_aud = payload["aud"]
        if cred_aud != "*" and cred_aud != audience:
            return _failure(
                ErrorCode.AUDIENCE_MISMATCH,
                f"Credential audience '{cred_aud}' does not match verifier '{audience}'",
            )

    return result


def verify_credential(
    credential_jwt: str,
    pin_store: KeyPinStore,
    audience: Optional[str],
    config: Optional[VerifierConfig] = None,
) -> VerificationResult:
    """Online verification that fetches discovery/revocation documents."""
    if config is None:
        config = VerifierConfig()

    # Parse JWT to extract issuer domain
    try:
        _header, payload, _sig = decode_jwt_unverified(credential_jwt)
    except Exception as e:
        return _failure(ErrorCode.ALGORITHM_REJECTED, f"JWT parse failed: {e}")

    # Fetch discovery document
    try:
        discovery = fetch_discovery_document(payload["iss"])
    except Exception as e:
        return _failure(ErrorCode.DISCOVERY_FETCH_FAILED, f"Failed to fetch discovery document: {e}")

    # Fetch revocation document
    revocation = None
    rev_endpoint = discovery.get("revocation_endpoint")
    if rev_endpoint:
        try:
            revocation = fetch_revocation_document(rev_endpoint)
        except Exception:
            return _failure(ErrorCode.DISCOVERY_FETCH_FAILED, "Revocation endpoint unreachable (fail-closed)")

    return verify_credential_offline(credential_jwt, discovery, revocation, pin_store, audience, config)
