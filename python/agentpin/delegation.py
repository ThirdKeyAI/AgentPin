"""Delegation attestation creation and verification for AgentPin."""

from typing import List

from .capability import Capability, capabilities_hash
from .crypto import sign_data, verify_signature
from .types import AgentPinError, ErrorCode


def canonical_attestation_input(
    domain: str,
    role: str,
    agent_id: str,
    delegatee_domain: str,
    delegatee_agent_id: str,
    capabilities: List[Capability],
) -> str:
    """Create the canonical attestation input string.

    Format: {domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{capabilities_hash}
    """
    cap_hash = capabilities_hash(capabilities)
    return f"{domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{cap_hash}"


def create_attestation(
    private_key_pem: str,
    kid: str,
    domain: str,
    role: str,
    agent_id: str,
    delegatee_domain: str,
    delegatee_agent_id: str,
    capabilities: List[Capability],
) -> dict:
    """Create a delegation attestation signed by the attesting entity."""
    input_str = canonical_attestation_input(domain, role, agent_id, delegatee_domain, delegatee_agent_id, capabilities)
    signature = sign_data(private_key_pem, input_str.encode("utf-8"))

    return {
        "domain": domain,
        "role": role,
        "agent_id": agent_id,
        "kid": kid,
        "attestation": signature,
    }


def verify_attestation(
    attestation: dict,
    public_key_pem: str,
    delegatee_domain: str,
    delegatee_agent_id: str,
    capabilities: List[Capability],
) -> None:
    """Verify a single delegation attestation signature.

    Raises:
        AgentPinError: if signature verification fails.
    """
    input_str = canonical_attestation_input(
        attestation["domain"],
        attestation["role"],
        attestation["agent_id"],
        delegatee_domain,
        delegatee_agent_id,
        capabilities,
    )

    valid = verify_signature(public_key_pem, input_str.encode("utf-8"), attestation["attestation"])
    if not valid:
        raise AgentPinError(
            ErrorCode.DELEGATION_INVALID,
            f"Delegation attestation from {attestation['domain']} failed signature verification",
        )


def verify_chain_depth(chain_len: int, max_depths: List[int]) -> None:
    """Verify the depth of a delegation chain does not exceed the minimum max_delegation_depth.

    Raises:
        AgentPinError: if chain depth exceeds limits.
    """
    min_depth = min(max_depths) if max_depths else 0
    if chain_len > min_depth:
        raise AgentPinError(
            ErrorCode.DELEGATION_DEPTH_EXCEEDED,
            f"Delegation chain depth {chain_len} exceeds minimum max_delegation_depth {min_depth}",
        )
