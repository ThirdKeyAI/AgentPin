"""Tests for JWK operations."""

import pytest

from agentpin.crypto import generate_key_pair
from agentpin.jwk import jwk_thumbprint, jwk_to_pem, pem_to_jwk


class TestJwkRoundtrip:
    def test_pem_jwk_pem(self):
        _, pub = generate_key_pair()
        jwk = pem_to_jwk(pub, "test-key-01")

        assert jwk["kty"] == "EC"
        assert jwk["crv"] == "P-256"
        assert jwk["kid"] == "test-key-01"
        assert jwk["use"] == "sig"

        pem_back = jwk_to_pem(jwk)
        assert pem_back == pub


class TestJwkThumbprint:
    def test_deterministic(self):
        _, pub = generate_key_pair()
        jwk = pem_to_jwk(pub, "kid-1")
        t1 = jwk_thumbprint(jwk)
        t2 = jwk_thumbprint(jwk)
        assert t1 == t2
        assert len(t1) == 64


class TestInvalidJwk:
    def test_rejects_rsa(self):
        jwk = {
            "kid": "bad",
            "kty": "RSA",
            "crv": "P-256",
            "x": "AAAA",
            "y": "BBBB",
            "use": "sig",
        }
        with pytest.raises(ValueError, match="Invalid JWK"):
            jwk_to_pem(jwk)
