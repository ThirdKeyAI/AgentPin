"""Regenerate testdata/conformance/vectors.json.

Run from the repository root with the Python SDK importable:

    python3 testdata/conformance/generate.py

Every vector is a must-reject (or must-accept) case that all four SDK test
suites load and check. Tokens are signed with the throwaway interop key
example-2026-01; they fail on structure, so they never expire.
"""

import base64
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from agentpin.a2a import sign_agent_card  # noqa: E402
from agentpin.crypto import domain_separated_input  # noqa: E402

with open(os.path.join(HERE, "example-2026-01.private.pem")) as fh:
    PRIV_PEM = fh.read()
PRIV = serialization.load_pem_private_key(PRIV_PEM.encode(), password=None)
with open(os.path.join(HERE, "discovery.json")) as fh:
    DISCOVERY = json.load(fh)

AGENT = "urn:agentpin:example.com:test-agent"
HEADER = {"alg": "ES256", "typ": "agentpin-credential+jwt", "kid": "example-2026-01"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(payload: dict) -> str:
    signing_input = b64url(json.dumps(HEADER).encode()) + "." + b64url(json.dumps(payload).encode())
    sig = PRIV.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    return signing_input + "." + b64url(sig)


def claims(**overrides) -> dict:
    base = {
        "iss": "example.com",
        "sub": AGENT,
        "iat": 1767225600,
        "exp": 1767229200,
        "jti": "conformance-0001",
        "agentpin_version": "0.1",
        "capabilities": ["read:data"],
    }
    for k, v in overrides.items():
        if v is None:
            base.pop(k, None)
        else:
            base[k] = v
    return base


credentials = [
    {"name": "missing_exp", "jwt": jwt(claims(exp=None)), "error_code": "MALFORMED_CREDENTIAL"},
    {"name": "string_exp", "jwt": jwt(claims(exp="1767229200")), "error_code": "MALFORMED_CREDENTIAL"},
    {"name": "missing_iat", "jwt": jwt(claims(iat=None)), "error_code": "MALFORMED_CREDENTIAL"},
    {"name": "iat_i64_min", "jwt": jwt(claims(iat=-9223372036854775808)), "error_code": "MALFORMED_CREDENTIAL"},
    {"name": "null_payload_fields", "jwt": jwt(claims(iss=None, sub=None)), "error_code": "MALFORMED_CREDENTIAL"},
    {"name": "capabilities_not_array", "jwt": jwt(claims(capabilities="read:data")),
     "error_code": "MALFORMED_CREDENTIAL"},
]

# Unknown top-level and nested fields must be preserved and covered by the
# signature (spec §4.10.1); tampering with one must break verification.
unsigned_card = {
    "name": "Conformance Agent",
    "description": "Card carrying fields AgentPin does not model",
    "url": "https://example.com/agents/test-agent",
    "version": "1.0.0",
    "capabilities": {"streaming": False, "pushNotifications": False},
    "skills": [{"id": "read-data", "name": "read:data", "description": "read data", "tags": ["read"]}],
    "defaultInputModes": ["text"],
    "provider": {"organization": "Example", "url": "https://example.com"},
    "x-vendor": {"tier": "gold", "regions": ["us", "eu"]},
}
card = sign_agent_card(unsigned_card, PRIV_PEM, "example-2026-01",
                       "https://example.com/.well-known/agent-identity.json")
tampered = json.loads(json.dumps(card))
tampered["x-vendor"]["tier"] = "platinum"

dsi_fields = ["nonce", "", "a\x00b"]
vectors = {
    "description": "Cross-SDK conformance vectors; regenerate with generate.py.",
    "discovery": "discovery.json",
    "credentials": credentials,
    "case_variant_issuer": {
        "comment": "Pin store already holds example.com with the interop key. A credential "
                   "with iss EXAMPLE.COM signed by a different key, backed by a discovery "
                   "document for EXAMPLE.COM listing only that key, must hit the existing pin.",
        "issuer": "EXAMPLE.COM",
        "error_code": "KEY_PIN_MISMATCH",
    },
    "revocation_wrong_field_names": {
        "comment": "Entries keyed by 'id' instead of jti/agent_id/kid. Typed SDKs may reject "
                   "at parse time; the others must return DISCOVERY_INVALID.",
        "document": {
            "agentpin_version": "0.1",
            "entity": "example.com",
            "updated_at": "2026-01-15T00:00:00Z",
            "revoked_credentials": [{"id": "conformance-0001", "revoked_at": "2026-01-15T00:00:00Z",
                                     "reason": "key_compromise"}],
            "revoked_agents": [],
            "revoked_keys": [{"id": "example-2026-01", "revoked_at": "2026-01-15T00:00:00Z",
                              "reason": "key_compromise"}],
        },
        "error_code": "DISCOVERY_INVALID",
    },
    "invalid_revocation_endpoints": [
        "http://example.com/.well-known/agent-identity-revocations.json",
        "https://evil.example.net/revocations.json",
        "https://example.com:8443/revocations.json",
        "https://user@example.com/revocations.json",
        "file:///etc/passwd",
    ],
    "agent_cards": [
        {"name": "extra_fields_signed", "card": card, "valid": True},
        {"name": "extra_field_tampered", "card": tampered, "valid": False},
    ],
    "domain_separated_input": {
        "context": "agentpin-response-v1",
        "fields_hex": [f.encode().hex() for f in dsi_fields],
        "expected_hex": domain_separated_input("agentpin-response-v1", [f.encode() for f in dsi_fields]).hex(),
    },
}

with open(os.path.join(HERE, "vectors.json"), "w") as fh:
    json.dump(vectors, fh, indent=2)
    fh.write("\n")
