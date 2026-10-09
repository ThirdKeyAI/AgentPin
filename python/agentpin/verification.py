"""Credential verification for AgentPin.

Implements the 12-step verification flow from the spec.
"""

import math
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .capability import Capability, validate_capability
from .constraint import merge_constraints
from .delegation import verify_attestation, verify_chain_depth
from .credential import validate_credential_against_discovery
from .discovery import fetch_discovery_document, find_agent_by_id, find_key_by_kid, validate_discovery_document
from .domain import default_revocation_endpoint, normalize_domain, validate_https_url_for_domain
from .jwk import jwk_to_pem
from .jwt import MalformedCredentialError, decode_jwt_unverified, verify_jwt
from .pinning import KeyPinStore, PinningResult, check_pinning
from .revocation import (
    check_revocation,
    check_revocation_freshness,
    fetch_revocation_document,
    fetch_revocation_document_if_present,
    verify_revocation_document,
)
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


def _parse_failure(exc: Exception) -> VerificationResult:
    """Claim-shape problems are MALFORMED_CREDENTIAL; everything else
    (structure, alg, typ) is ALGORITHM_REJECTED."""
    if isinstance(exc, MalformedCredentialError):
        return _failure(ErrorCode.MALFORMED_CREDENTIAL, exc.reason)
    return _failure(ErrorCode.ALGORITHM_REJECTED, f"JWT parse failed: {exc}")


DEFAULT_CREDENTIAL_TTL_MAX = 86400
"""Default ``credential_ttl_max`` when an agent declaration omits it (spec §4.5)."""


def _is_nonneg_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_key_usable(jwk: dict, now: int, skew: int) -> None:
    """Reject keys that are expired, not marked for signature use, or whose
    ``key_ops`` exclude ``verify`` (spec §4.4; AP-20, AP-21). An unparsable
    ``exp`` is a failure, not a pass.

    Raises:
        AgentPinError: KEY_EXPIRED or KEY_NOT_FOUND
    """
    kid = jwk.get("kid")
    exp = jwk.get("exp")
    if exp is not None:
        try:
            exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            raise AgentPinError(ErrorCode.KEY_EXPIRED, f"Key '{kid}' has an unparsable exp '{exp}'") from None
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if exp_dt.timestamp() < now - skew:
            raise AgentPinError(ErrorCode.KEY_EXPIRED, f"Key '{kid}' has expired")
    if jwk.get("use") != "sig":
        raise AgentPinError(ErrorCode.KEY_NOT_FOUND, f"Key '{kid}' is not a signature key (use = '{jwk.get('use')}')")
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise AgentPinError(ErrorCode.KEY_NOT_FOUND, f"Key '{kid}' key_ops do not permit verify")


def _verify_delegation_chain(chain, issuer, payload, discovery, chain_resolver, now, skew):
    """Spec §6.4: verify every attestation against its attester's discovery
    document, check Maker/Deployer scope narrowing, and enforce the minimum
    max_delegation_depth across all participants.

    Returns (entries, None) on success or (None, failure_result).
    """

    def fail(message):
        return None, _failure(ErrorCode.DELEGATION_INVALID, message)

    depths = [discovery.get("max_delegation_depth", 0)]
    entries = []
    for att in chain:
        try:
            domain = normalize_domain(att.get("domain"))
        except AgentPinError as e:
            return fail(f"Delegation attester domain invalid: {e}")
        try:
            doc = chain_resolver.resolve_discovery(domain)
            validate_discovery_document(doc, domain)
        except Exception as e:
            return fail(f"Cannot resolve discovery document for delegation attester '{domain}': {e}")
        jwk = find_key_by_kid(doc, att.get("kid"))
        if not jwk:
            return fail(f"Delegation attester '{domain}' has no key '{att.get('kid')}'")
        try:
            check_key_usable(jwk, now, skew)
            pem = jwk_to_pem(jwk)
        except Exception as e:
            return fail(f"Delegation attester '{domain}' key '{att.get('kid')}' unusable: {e}")
        try:
            verify_attestation(att, pem, issuer, payload["sub"], payload.get("capabilities", []))
        except AgentPinError as e:
            return fail(str(e))
        # Scope narrowing (spec §10.3): when the attester declares the
        # attested agent, it must be active and the credential capabilities
        # must be within what the attester declared for it.
        agent = find_agent_by_id(doc, att.get("agent_id"))
        if agent is not None:
            if agent.get("status") != "active":
                return fail(f"Delegation attester '{domain}' declares agent '{att.get('agent_id')}' as {agent.get('status')}")
            try:
                validate_credential_against_discovery(payload.get("capabilities", []), agent.get("capabilities", []))
            except AgentPinError:
                return fail(
                    f"Credential capabilities exceed those declared by delegation attester '{domain}' "
                    f"for '{att.get('agent_id')}'"
                )
        depths.append(doc.get("max_delegation_depth", 0))
        entries.append({"domain": domain, "role": att.get("role"), "verified": True})
    try:
        verify_chain_depth(len(chain), depths)
    except AgentPinError as e:
        return None, _failure(e.code, str(e))
    return entries, None


def verify_credential_offline(
    credential_jwt: str,
    discovery: dict,
    revocation: Optional[dict],
    pin_store: KeyPinStore,
    audience: Optional[str],
    config: Optional[VerifierConfig] = None,
    chain_resolver: Optional[Any] = None,
) -> VerificationResult:
    """Verify a credential offline using caller-provided documents.

    Implements the 12-step verification flow from the spec.

    Without ``chain_resolver`` a ``delegation_chain`` cannot be verified;
    under the default ``require_delegation_verification=True`` such a
    credential is rejected. Pass an object with a synchronous
    ``resolve_discovery(domain)`` (for example a trust bundle lookup) to
    verify chains offline.
    """
    if config is None:
        config = VerifierConfig()

    # Step 1: Parse JWT (alg/typ, then claim shape — AP-5 / AP-18)
    try:
        header, payload, _sig = decode_jwt_unverified(credential_jwt)
    except Exception as e:
        return _parse_failure(e)

    # Normalize the issuer domain before it is used as a lookup key anywhere
    # (pin store, entity comparison, resolver paths/URLs) — AP-3.
    try:
        issuer = normalize_domain(payload.get("iss"))
    except AgentPinError as e:
        return _failure(ErrorCode.DISCOVERY_INVALID, f"Invalid issuer domain: {e}")

    # Step 2: Check temporal validity
    now = math.floor(time.time())
    skew = config.clock_skew_secs

    if payload["iat"] > now + skew:
        return _failure(ErrorCode.CREDENTIAL_EXPIRED, "Credential issued in the future")
    if payload["exp"] <= now - skew:
        return _failure(ErrorCode.CREDENTIAL_EXPIRED, "Credential has expired")
    nbf = payload.get("nbf")
    if nbf is not None and nbf > now + skew:
        return _failure(ErrorCode.CREDENTIAL_EXPIRED, "Credential not yet valid (nbf)")

    # Claims were validated as non-negative integers with exp > iat (AP-14).
    lifetime = payload["exp"] - payload["iat"]
    if lifetime <= 0:
        return _failure(ErrorCode.MALFORMED_CREDENTIAL, "exp must be greater than iat")
    if lifetime > config.max_ttl_secs:
        return _failure(
            ErrorCode.CREDENTIAL_EXPIRED,
            f"Credential lifetime {lifetime} exceeds max TTL {config.max_ttl_secs}",
        )

    # Step 3: Validate discovery document
    try:
        validate_discovery_document(discovery, issuer)
    except AgentPinError as e:
        return _failure(ErrorCode.DISCOVERY_INVALID, f"Discovery validation failed: {e}")

    # Step 4: Resolve public key by kid
    jwk = find_key_by_kid(discovery, header["kid"])
    if not jwk:
        return _failure(ErrorCode.KEY_NOT_FOUND, f"Key '{header['kid']}' not found in discovery document")

    # Check key expiration and usage (an unparsable exp is a failure, not a
    # pass — AP-20; use/key_ops enforced — AP-21)
    try:
        check_key_usable(jwk, now, skew)
    except AgentPinError as e:
        return _failure(e.code, str(e))

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

    # Step 6: Check revocation. The document must belong to this issuer and,
    # when signed, verify under a discovery key (design issue 3).
    if revocation:
        try:
            verify_revocation_document(revocation, discovery)
        except AgentPinError as e:
            return _failure(ErrorCode.DISCOVERY_INVALID, f"Revocation document invalid: {e}")
        if config.require_signed_revocation and revocation.get("signature") is None:
            return _failure(ErrorCode.DISCOVERY_INVALID, "Revocation document is not signed")
        if config.revocation_max_age_secs is not None:
            try:
                check_revocation_freshness(revocation, config.revocation_max_age_secs)
            except AgentPinError as e:
                return _failure(ErrorCode.DISCOVERY_INVALID, f"Revocation document invalid: {e}")
        try:
            check_revocation(revocation, payload["jti"], payload["sub"], header["kid"])
        except AgentPinError as e:
            return _failure(e.code, str(e))
        except (KeyError, TypeError, AttributeError) as e:
            return _failure(ErrorCode.DISCOVERY_INVALID, f"Revocation document invalid: {e}")

    # Step 7: Validate agent status
    agent = find_agent_by_id(discovery, payload["sub"])
    if not agent:
        return _failure(ErrorCode.AGENT_NOT_FOUND, f"Agent '{payload['sub']}' not found in discovery document")
    if agent.get("status") != "active":
        return _failure(ErrorCode.AGENT_INACTIVE, f"Agent '{payload['sub']}' status is {agent.get('status')}")

    # Spec §5.7: exp - iat MUST NOT exceed the agent's credential_ttl_max
    # (default 86400 when omitted) — AP-14.
    ttl_max = agent.get("credential_ttl_max")
    if not _is_nonneg_int(ttl_max):
        ttl_max = DEFAULT_CREDENTIAL_TTL_MAX
    if lifetime > ttl_max:
        return _failure(
            ErrorCode.CREDENTIAL_EXPIRED,
            f"Credential lifetime {lifetime} exceeds agent credential_ttl_max {ttl_max}",
        )

    # Step 8: Validate capabilities. admin MUST NOT be granted via wildcard
    # (spec §10.3); under strict_capabilities every capability on both sides
    # must satisfy the taxonomy (AP-21).
    for cap in payload.get("capabilities", []):
        if Capability.parse(str(cap)) == ("admin", "*"):
            return _failure(
                ErrorCode.CAPABILITY_EXCEEDED, f"Capability '{cap}' is not allowed: admin must be explicitly scoped"
            )
    if config.strict_capabilities:
        for cap in list(payload.get("capabilities", [])) + list(agent.get("capabilities", []) or []):
            try:
                validate_capability(cap if isinstance(cap, Capability) else Capability(str(cap)))
            except ValueError as e:
                return _failure(ErrorCode.CAPABILITY_EXCEEDED, f"Capability '{cap}' rejected: {e}")
    try:
        validate_credential_against_discovery(payload.get("capabilities", []), agent.get("capabilities", []))
    except AgentPinError as e:
        return _failure(ErrorCode.CAPABILITY_EXCEEDED, str(e))

    # Step 9: Validate constraints and compute the effective (merged) set the
    # consumer must enforce: discovery defaults narrowed by the credential
    # (AP-15).
    try:
        effective_constraints = merge_constraints(agent.get("constraints"), payload.get("constraints"))
    except ValueError as e:
        return _failure(
            ErrorCode.CONSTRAINT_VIOLATION,
            f"Credential constraints are less restrictive than discovery defaults: {e}",
        )

    # Step 10: Delegation chain (offline: note only)
    result = _success(
        payload["sub"],
        issuer,
        payload.get("capabilities", []),
        effective_constraints,
        {"status": "unknown", "first_seen": None},
    )

    # Step 10: every attestation is verified against its attester's
    # discovery document (spec §6.4); a chain that cannot be verified fails
    # closed unless the verifier opted out (AP-2).
    chain = payload.get("delegation_chain")
    if chain:
        if chain_resolver is not None:
            entries, failed = _verify_delegation_chain(chain, issuer, payload, discovery, chain_resolver, now, skew)
            if failed is not None:
                return failed
            result.delegation_chain = entries
            result.delegation_verified = True
        elif config.require_delegation_verification:
            return _failure(
                ErrorCode.DELEGATION_INVALID, "Delegation chain present but no resolver is available to verify it"
            )
        else:
            result.delegation_chain = [
                {"domain": att.get("domain"), "role": att.get("role"), "verified": False} for att in chain
            ]
            result.delegation_verified = False
            result.warnings.append(
                "Delegation chain present but not verified (require_delegation_verification is False)"
            )

    # Step 11: TOFU key pinning
    try:
        pin_result = check_pinning(pin_store, issuer, jwk)
        if pin_result == PinningResult.FIRST_USE:
            result.key_pinning = {"status": "first_use", "first_seen": datetime.now(timezone.utc).isoformat()}
        elif pin_result == PinningResult.MATCHED:
            domain_data = pin_store.get_domain(issuer)
            first_seen = None
            if domain_data and domain_data.get("pinned_keys"):
                first_seen = domain_data["pinned_keys"][0].get("first_seen")
            result.key_pinning = {"status": "pinned", "first_seen": first_seen}
    except AgentPinError:
        return _failure(ErrorCode.KEY_PIN_MISMATCH, f"Key for '{issuer}' has changed since last pinned")

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
        return _parse_failure(e)

    try:
        issuer = normalize_domain(payload.get("iss"))
    except AgentPinError as e:
        return _failure(ErrorCode.DISCOVERY_INVALID, f"Invalid issuer domain: {e}")

    # Fetch discovery document
    try:
        discovery = fetch_discovery_document(issuer)
    except Exception as e:
        return _failure(ErrorCode.DISCOVERY_FETCH_FAILED, f"Failed to fetch discovery document: {e}")

    # Fetch revocation document (https on the issuer's own host only — AP-12).
    # An explicitly declared endpoint fails closed on any error; when none is
    # declared the spec §8.1 default URL is used and only a 404 there means
    # "no revocations published" (design issue 3).
    revocation = None
    rev_endpoint = discovery.get("revocation_endpoint")
    if rev_endpoint:
        try:
            validate_https_url_for_domain(rev_endpoint, issuer)
        except AgentPinError as e:
            return _failure(ErrorCode.DISCOVERY_INVALID, f"Invalid revocation_endpoint: {e}")
        try:
            revocation = fetch_revocation_document(rev_endpoint)
        except Exception:
            return _failure(ErrorCode.DISCOVERY_FETCH_FAILED, "Revocation endpoint unreachable (fail-closed)")
    else:
        try:
            revocation = fetch_revocation_document_if_present(default_revocation_endpoint(issuer))
        except Exception:
            return _failure(ErrorCode.DISCOVERY_FETCH_FAILED, "Revocation endpoint unreachable (fail-closed)")

    # Pre-resolve the discovery documents of every delegation attester so the
    # chain can be verified by the synchronous core (AP-2).
    chain_docs: Dict[str, dict] = {}
    for att in payload.get("delegation_chain") or []:
        try:
            domain = normalize_domain(att.get("domain"))
        except AgentPinError as e:
            return _failure(ErrorCode.DELEGATION_INVALID, f"Delegation attester domain invalid: {e}")
        if domain in chain_docs:
            continue
        try:
            chain_docs[domain] = fetch_discovery_document(domain)
        except Exception as e:
            return _failure(
                ErrorCode.DELEGATION_INVALID,
                f"Cannot resolve discovery document for delegation attester '{domain}': {e}",
            )

    class _PreResolved:
        def resolve_discovery(self, domain: str) -> dict:
            doc = chain_docs.get(normalize_domain(domain))
            if doc is None:
                raise AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, f"Domain '{domain}' not pre-resolved")
            return doc

    return verify_credential_offline(
        credential_jwt, discovery, revocation, pin_store, audience, config, chain_resolver=_PreResolved()
    )
