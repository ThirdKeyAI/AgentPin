"""Tests for mutual authentication challenge-response."""

import base64
from datetime import datetime, timedelta, timezone

import pytest

from agentpin.crypto import generate_key_pair
from agentpin.mutual import create_challenge, create_response, verify_response


class TestChallengeResponse:
    def test_roundtrip(self):
        priv, pub = generate_key_pair()
        challenge = create_challenge()
        assert challenge["type"] == "agentpin-challenge"
        assert challenge["nonce"]

        response = create_response(challenge, priv, "test-key")
        assert response["type"] == "agentpin-response"
        assert response["nonce"] == challenge["nonce"]

        valid = verify_response(response, challenge, pub)
        assert valid

    def test_wrong_key_rejected(self):
        priv1, _ = generate_key_pair()
        _, pub2 = generate_key_pair()
        challenge = create_challenge()
        response = create_response(challenge, priv1, "key1")
        valid = verify_response(response, challenge, pub2)
        assert not valid

    def test_nonce_mismatch_rejected(self):
        priv, pub = generate_key_pair()
        challenge = create_challenge()
        response = create_response(challenge, priv, "test-key")
        response["nonce"] = "wrong-nonce"
        valid = verify_response(response, challenge, pub)
        assert not valid

    def test_expired_nonce_rejected(self):
        priv, pub = generate_key_pair()
        challenge = create_challenge()
        past = datetime.now(timezone.utc) - timedelta(seconds=120)
        challenge["timestamp"] = past.isoformat()

        response = create_response(challenge, priv, "test-key")
        with pytest.raises(ValueError, match="expired"):
            verify_response(response, challenge, pub)

    def test_nonce_is_128_bits(self):
        challenge = create_challenge()
        nonce = challenge["nonce"]
        # Restore padding for base64url decode
        padding = 4 - len(nonce) % 4
        if padding != 4:
            nonce += "=" * padding
        nonce_bytes = base64.urlsafe_b64decode(nonce)
        assert len(nonce_bytes) == 16  # 128 bits

    def test_with_verifier_credential(self):
        challenge = create_challenge("eyJ...test-jwt")
        assert challenge["verifier_credential"] == "eyJ...test-jwt"
