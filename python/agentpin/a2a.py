"""A2A AgentCard signing and verification (v0.3.0).

Mirrors the Rust ``agentpin::a2a`` module. AgentPin extends the Google A2A
AgentCard format with cryptographic identity verification. The ``agentpin``
extension carries the AgentPin endpoint URL, the entity's public key in JWK
form, and a detached ECDSA P-256 signature over the canonical bytes of the
rest of the AgentCard.

Canonicalization: the signing input is the AgentCard with its ``agentpin``
field replaced by ``{"agentpin_endpoint", "public_key_jwk"}`` (signature
cleared), JSON-serialized with sorted keys and compact separators and wrapped
in the ``agentpin-agentcard-v1`` signing context. The endpoint and key are
therefore covered by the signature (AP-4) and card signatures are disjoint
from every other AgentPin signature (AP-1).
"""

import json
from typing import Any, Dict, List, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .crypto import CTX_AGENTCARD, domain_separated_input, sign_data, verify_signature
from .discovery import AllowedDomains
from .jwk import jwk_thumbprint, jwk_to_pem, pem_to_jwk
from .types import AgentPinError, ErrorCode


# ---------------------------------------------------------------------------
# Capability -> Skill mapping
# ---------------------------------------------------------------------------


def capability_to_skill(cap: Union[str, dict]) -> dict:
    """Map an AgentPin capability (string or ``{"id": ...}`` dict) to a skill."""
    if isinstance(cap, dict):
        id_ = cap.get("id", str(cap))
    else:
        id_ = str(cap)
    return {"id": id_, "name": id_}


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_unsigned_agent_card(
    url: str,
    declaration: dict,
    *,
    skills: Optional[List[dict]] = None,
    streaming: bool = False,
    push_notifications: bool = False,
) -> dict:
    """Build an unsigned A2A AgentCard from an AgentPin ``AgentDeclaration``.

    Capabilities map 1:1 to skills via ``capability_to_skill``; the
    ``allowed_domains`` constraint is copied into ``capabilities.allowed_domains``
    (omitted entirely when unrestricted, matching the Rust serde behaviour).
    """
    if skills is None or len(skills) == 0:
        out_skills = [capability_to_skill(c) for c in declaration.get("capabilities", [])]
    else:
        out_skills = [dict(s) for s in skills]

    allowed_domains = AllowedDomains.from_constraints(declaration.get("constraints"))

    capabilities: Dict[str, Any] = {
        "streaming": bool(streaming),
        "pushNotifications": bool(push_notifications),
    }
    if not AllowedDomains.is_unrestricted(allowed_domains):
        capabilities["allowed_domains"] = list(allowed_domains)

    card: Dict[str, Any] = {
        "name": declaration["name"],
        "url": url,
        "capabilities": capabilities,
        "skills": out_skills,
    }
    if declaration.get("description") is not None:
        card["description"] = declaration["description"]
    if declaration.get("version") is not None:
        card["version"] = declaration["version"]
    return card


def sign_agent_card(
    unsigned_card: dict,
    private_key_pem: str,
    kid: str,
    agentpin_endpoint: str,
) -> dict:
    """Sign an A2A AgentCard with an ECDSA P-256 private key (PEM).

    Returns the input card with the ``agentpin`` extension populated.
    """
    if not agentpin_endpoint:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "sign_agent_card requires agentpin_endpoint",
        )

    # Derive the public-key JWK from the private key.
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"), password=None
    )
    assert isinstance(private_key, EllipticCurvePrivateKey)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    public_jwk = pem_to_jwk(public_pem, kid)

    # Sign over the domain-separated canonical bytes with the endpoint and
    # JWK included.
    signature = sign_data(
        private_key_pem, _agent_card_signing_input_for(unsigned_card, agentpin_endpoint, public_jwk)
    )

    signed = dict(unsigned_card)
    signed["agentpin"] = {
        "agentpin_endpoint": agentpin_endpoint,
        "public_key_jwk": public_jwk,
        "signature": signature,
    }
    return signed


def build_and_sign_agent_card(
    url: str,
    declaration: dict,
    private_key_pem: str,
    kid: str,
    agentpin_endpoint: str,
    *,
    skills: Optional[List[dict]] = None,
    streaming: bool = False,
    push_notifications: bool = False,
) -> dict:
    """One-shot helper: build + sign in a single call."""
    unsigned = build_unsigned_agent_card(
        url,
        declaration,
        skills=skills,
        streaming=streaming,
        push_notifications=push_notifications,
    )
    return sign_agent_card(unsigned, private_key_pem, kid, agentpin_endpoint)


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_agentpin_extension(card: dict) -> None:
    """Verify the ``agentpin`` extension on an A2A AgentCard.

    Raises ``AgentPinError(DISCOVERY_INVALID)`` on any failure (extension
    missing, malformed JWK, signature mismatch).

    This proves only that the card has not been tampered with relative to the
    key inside its own extension. Pair with ``A2aAgentCardResolver`` for the
    full chain back to a trusted AgentPin discovery document.
    """
    ext = card.get("agentpin") if card else None
    if not ext:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID, "AgentCard has no agentpin extension"
        )

    input_bytes = agent_card_signing_input(card)
    public_pem = jwk_to_pem(ext["public_key_jwk"])
    ok = verify_signature(public_pem, input_bytes, str(ext.get("signature", "")))
    if not ok:
        raise AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            "A2A AgentCard signature did not verify against extension JWK",
        )


def extension_key_thumbprint(extension: dict) -> str:
    """JWK thumbprint of the public key carried in a card's ``agentpin`` extension."""
    return jwk_thumbprint(extension["public_key_jwk"])


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------


def agent_card_signing_input(card: dict) -> bytes:
    """The domain-separated bytes ``card["agentpin"]["signature"]`` must verify against.

    Uses the endpoint and JWK from the card's own extension.
    """
    ext = card.get("agentpin") if card else None
    if not ext:
        raise AgentPinError(ErrorCode.DISCOVERY_INVALID, "AgentCard has no agentpin extension")
    return _agent_card_signing_input_for(card, ext.get("agentpin_endpoint"), ext.get("public_key_jwk"))


def _agent_card_signing_input_for(card: dict, agentpin_endpoint: object, public_key_jwk: object) -> bytes:
    for_signing = {k: v for k, v in card.items() if k != "agentpin"}
    for_signing["agentpin"] = {
        "agentpin_endpoint": agentpin_endpoint,
        "public_key_jwk": public_key_jwk,
    }
    canonical = canonicalize_for_signing(for_signing)
    return domain_separated_input(CTX_AGENTCARD, [canonical.encode("utf-8")])


def canonicalize_for_signing(value: Any) -> str:
    """Canonical JSON: sorted object keys, compact separators.

    Drops ``None`` values from objects so they round-trip identically with the
    Rust SDK's ``skip_serializing_if = "Option::is_none"`` behaviour.
    """
    return json.dumps(
        _sorted_canonical(value),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sorted_canonical(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k in sorted(value.keys()):
            v = value[k]
            if v is None:
                continue
            out[k] = _sorted_canonical(v)
        return out
    if isinstance(value, list):
        return [_sorted_canonical(v) for v in value]
    return value
