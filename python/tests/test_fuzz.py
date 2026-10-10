"""Property-based fuzzing of parsers that consume untrusted input.

Each property asserts the parser fails only with a controlled error
(AgentPinError or ValueError), never an incidental TypeError/KeyError.
"""

import base64
import json

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from agentpin.a2a import agent_card_signing_input, verify_agentpin_extension  # noqa: E402
from agentpin.discovery import validate_discovery_document  # noqa: E402
from agentpin.dns import parse_txt_record  # noqa: E402
from agentpin.jwk import jwk_thumbprint, jwk_to_pem  # noqa: E402
from agentpin.jwt import decode_jwt_unverified, validate_claims  # noqa: E402
from agentpin.pinning import KeyPinStore  # noqa: E402
from agentpin.types import AgentPinError  # noqa: E402
from agentpin.verification import verify_credential_offline  # noqa: E402

CONTROLLED = (AgentPinError, ValueError)
FUZZ = settings(max_examples=300, deadline=None)

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=20,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


jwt_like = st.tuples(json_values, json_values, st.text()).map(
    lambda t: f"{_b64(json.dumps(t[0]).encode())}.{_b64(json.dumps(t[1]).encode())}.{t[2]}"
)


def controlled(fn, *args):
    try:
        return fn(*args)
    except CONTROLLED:
        return None


@FUZZ
@given(st.one_of(st.text(), jwt_like))
def test_decode_jwt_unverified(s):
    decoded = controlled(decode_jwt_unverified, s)
    if decoded is not None:
        controlled(validate_claims, decoded[1])


@FUZZ
@given(st.one_of(st.text(), jwt_like))
def test_verify_credential_offline_never_raises(s):
    disc = {"agentpin_version": "0.1", "entity": "example.com", "public_keys": [], "agents": []}
    assert not verify_credential_offline(s, disc, None, KeyPinStore(), None).valid


@FUZZ
@given(st.text())
def test_parse_txt_record(s):
    controlled(parse_txt_record, s)


@FUZZ
@given(st.fixed_dictionaries({
    "kid": st.text(), "kty": st.sampled_from(["EC", "RSA"]), "crv": st.sampled_from(["P-256", "P-384"]),
    "x": st.text(), "y": st.text(), "use": st.text(),
}))
def test_jwk_conversion(jwk):
    controlled(jwk_to_pem, jwk)
    controlled(jwk_thumbprint, jwk)


@FUZZ
@given(json_values)
def test_validate_discovery_document(doc):
    controlled(validate_discovery_document, doc, "example.com")


@FUZZ
@given(st.fixed_dictionaries({
    "name": st.text(), "url": st.text(),
    "capabilities": st.dictionaries(st.text(), json_values),
    "skills": st.lists(st.dictionaries(st.text(), json_values), max_size=3),
    "extra": json_values,
}))
def test_agent_card_canonicalization_stable(card):
    first = controlled(agent_card_signing_input, card)
    if first is None:
        return
    assert agent_card_signing_input(json.loads(json.dumps(card))) == first
    controlled(verify_agentpin_extension, card)
