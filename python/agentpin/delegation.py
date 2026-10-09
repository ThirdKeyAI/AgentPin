"""Delegation attestation creation and verification for AgentPin (spec §5.6 / §6.4).

An attestation is a signature over the domain-separated structure::

    "agentpin-attestation-v1" 0x00 len(domain) domain len(role) role
        len(agent_id) agent_id len(delegatee_domain) delegatee_domain
        len(delegatee_agent_id) delegatee_agent_id
        len(capabilities_hash) capabilities_hash len(kid) kid len(exp) exp

``kid`` binds the attestation to the attesting key; ``exp`` (decimal Unix
seconds, empty when absent) bounds its lifetime.
"""

import time
from typing import List, Optional

from .capability import Capability, capabilities_hash
from .crypto import CTX_ATTESTATION, domain_separated_input, sign_data, verify_signature
from .types import AgentPinError, ErrorCode


def canonical_attestation_input(
    domain: str,
    role: str,
    agent_id: str,
    delegatee_domain: str,
    delegatee_agent_id: str,
    capabilities: List[Capability],
    kid: str,
    exp: Optional[int] = None,
) -> bytes:
    """Create the domain-separated attestation signing input."""
    cap_hash = capabilities_hash(capabilities)
    exp_str = "" if exp is None else str(int(exp))
    return domain_separated_input(
        CTX_ATTESTATION,
        [
            str(domain),
            str(role),
            str(agent_id),
            str(delegatee_domain),
            str(delegatee_agent_id),
            cap_hash,
            str(kid),
            exp_str,
        ],
    )


def create_attestation(
    private_key_pem: str,
    kid: str,
    domain: str,
    role: str,
    agent_id: str,
    delegatee_domain: str,
    delegatee_agent_id: str,
    capabilities: List[Capability],
    exp: Optional[int] = None,
) -> dict:
    """Create a delegation attestation signed by the attesting entity.

    ``exp`` is an optional attestation expiry (Unix seconds), covered by the
    signature.
    """
    input_bytes = canonical_attestation_input(
        domain, role, agent_id, delegatee_domain, delegatee_agent_id, capabilities, kid, exp
    )
    signature = sign_data(private_key_pem, input_bytes)

    att = {
        "domain": domain,
        "role": role,
        "agent_id": agent_id,
        "kid": kid,
        "attestation": signature,
    }
    if exp is not None:
        att["exp"] = int(exp)
    return att


def verify_attestation(
    attestation: dict,
    public_key_pem: str,
    delegatee_domain: str,
    delegatee_agent_id: str,
    capabilities: List[Capability],
) -> None:
    """Verify a single delegation attestation signature (and expiry, when present).

    Raises:
        AgentPinError: if signature verification fails or the attestation expired.
    """
    exp = attestation.get("exp")
    if exp is not None:
        if not isinstance(exp, int) or isinstance(exp, bool) or exp < int(time.time()):
            raise AgentPinError(
                ErrorCode.DELEGATION_INVALID,
                f"Delegation attestation from {attestation.get('domain')} has expired",
            )
    input_bytes = canonical_attestation_input(
        str(attestation.get("domain", "")),
        str(attestation.get("role", "")),
        str(attestation.get("agent_id", "")),
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
        str(attestation.get("kid", "")),
        exp,
    )

    valid = verify_signature(public_key_pem, input_bytes, str(attestation.get("attestation", "")))
    if not valid:
        raise AgentPinError(
            ErrorCode.DELEGATION_INVALID,
            f"Delegation attestation from {attestation.get('domain')} failed signature verification",
        )


def verify_chain_depth(chain_len: int, max_depths: List[int]) -> None:
    """Verify the depth of a delegation chain does not exceed the minimum max_delegation_depth.

    An empty depth list means depth 0 (no delegation permitted).

    Raises:
        AgentPinError: if chain depth exceeds limits.
    """
    min_depth = min(max_depths) if max_depths else 0
    if chain_len > min_depth:
        raise AgentPinError(
            ErrorCode.DELEGATION_DEPTH_EXCEEDED,
            f"Delegation chain depth {chain_len} exceeds minimum max_delegation_depth {min_depth}",
        )
