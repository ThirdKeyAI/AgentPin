"""Agent credential issuance and validation for AgentPin."""

import math
import uuid
from typing import List, Optional

from .capability import Capability, capabilities_subset
from .jwt import encode_jwt
from .types import AgentPinError, ErrorCode


def issue_credential(
    private_key_pem: str,
    kid: str,
    issuer: str,
    agent_id: str,
    audience: Optional[str],
    capabilities: List[Capability],
    constraints: Optional[dict],
    delegation_chain: Optional[list],
    ttl_secs: int,
) -> str:
    """Issue a new agent credential JWT."""
    import time

    now = math.floor(time.time())

    header = {
        "alg": "ES256",
        "typ": "agentpin-credential+jwt",
        "kid": kid,
    }

    payload: dict = {
        "iss": issuer,
        "sub": agent_id,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": str(uuid.uuid4()),
        "agentpin_version": "0.1",
        "capabilities": [c.value if isinstance(c, Capability) else c for c in capabilities],
    }

    if audience:
        payload["aud"] = audience
    if constraints:
        payload["constraints"] = constraints
    if delegation_chain:
        payload["delegation_chain"] = delegation_chain

    return encode_jwt(header, payload, private_key_pem)


def validate_credential_against_discovery(
    credential_caps: List,
    discovery_caps: List,
) -> None:
    """Validate that credential capabilities are a subset of discovery agent capabilities.

    Raises:
        AgentPinError: if capabilities exceed discovery
    """
    cred = [c if isinstance(c, Capability) else Capability(c) for c in credential_caps]
    disc = [c if isinstance(c, Capability) else Capability(c) for c in discovery_caps]

    if not capabilities_subset(disc, cred):
        raise AgentPinError(ErrorCode.CAPABILITY_EXCEEDED, "Credential capabilities exceed discovery document")
