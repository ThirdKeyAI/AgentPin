"""Tests for JWT encode/decode/verify."""

import pytest

from agentpin.crypto import generate_key_pair
from agentpin.jwt import decode_jwt_unverified, encode_jwt, verify_jwt


def make_test_jwt(private_key_pem, kid):
    header = {"alg": "ES256", "typ": "agentpin-credential+jwt", "kid": kid}
    payload = {
        "iss": "example.com",
        "sub": "urn:agentpin:example.com:agent",
        "aud": "verifier.com",
        "iat": 1738300800,
        "exp": 1738304400,
        "jti": "test-jti-001",
        "agentpin_version": "0.1",
        "capabilities": ["read:data"],
    }
    jwt_str = encode_jwt(header, payload, private_key_pem)
    return jwt_str, header, payload


class TestJwtRoundtrip:
    def test_encode_and_verify(self):
        priv, pub = generate_key_pair()
        jwt_str, orig_header, orig_payload = make_test_jwt(priv, "test-key")
        header, payload = verify_jwt(jwt_str, pub)
        assert header["alg"] == orig_header["alg"]
        assert header["typ"] == orig_header["typ"]
        assert header["kid"] == orig_header["kid"]
        assert payload["iss"] == orig_payload["iss"]
        assert payload["sub"] == orig_payload["sub"]


class TestJwtSecurity:
    def test_wrong_key_rejected(self):
        priv1, _ = generate_key_pair()
        _, pub2 = generate_key_pair()
        jwt_str, _, _ = make_test_jwt(priv1, "key1")
        with pytest.raises(ValueError):
            verify_jwt(jwt_str, pub2)

    def test_wrong_algorithm_rejected(self):
        priv, _ = generate_key_pair()
        header = {"alg": "none", "typ": "agentpin-credential+jwt", "kid": "test"}
        payload = {
            "iss": "example.com",
            "sub": "urn:agentpin:example.com:agent",
            "iat": 1738300800,
            "exp": 1738304400,
            "jti": "jti",
            "agentpin_version": "0.1",
            "capabilities": [],
        }
        jwt_str = encode_jwt(header, payload, priv)
        with pytest.raises(ValueError, match="rejected"):
            decode_jwt_unverified(jwt_str)

    def test_wrong_type_rejected(self):
        priv, _ = generate_key_pair()
        header = {"alg": "ES256", "typ": "JWT", "kid": "test"}
        payload = {
            "iss": "example.com",
            "sub": "urn:agentpin:example.com:agent",
            "iat": 1738300800,
            "exp": 1738304400,
            "jti": "jti",
            "agentpin_version": "0.1",
            "capabilities": [],
        }
        jwt_str = encode_jwt(header, payload, priv)
        with pytest.raises(ValueError, match="rejected"):
            decode_jwt_unverified(jwt_str)

    def test_malformed_rejected(self):
        with pytest.raises(ValueError):
            decode_jwt_unverified("not.a.jwt.token")
        with pytest.raises(ValueError):
            decode_jwt_unverified("only-one-part")
