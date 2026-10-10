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


class TestChallengeResponseHardening:
    """AP-1 / AP-19 regression tests."""

    def test_default_nonce_store_rejects_replay(self):
        priv, pub = generate_key_pair()
        challenge = create_challenge()
        response = create_response(challenge, priv, "k")
        assert verify_response(response, challenge, pub)
        with pytest.raises(ValueError, match="already been used"):
            verify_response(response, challenge, pub)

    def test_forged_response_does_not_consume_nonce(self):
        priv, pub = generate_key_pair()
        attacker_priv, _ = generate_key_pair()
        challenge = create_challenge()
        forged = create_response(challenge, attacker_priv, "k")
        assert verify_response(forged, challenge, pub) is False
        genuine = create_response(challenge, priv, "k")
        assert verify_response(genuine, challenge, pub)

    def test_malformed_timestamp_treated_as_expired(self):
        priv, pub = generate_key_pair()
        challenge = create_challenge()
        challenge["timestamp"] = "not-a-timestamp"
        response = create_response(challenge, priv, "k")
        with pytest.raises(ValueError, match="timestamp"):
            verify_response(response, challenge, pub)

    def test_create_response_rejects_jwt_shaped_or_non_canonical_nonce(self):
        priv, _ = generate_key_pair()
        challenge = create_challenge()
        header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"k"}').rstrip(b"=")
        payload = base64.urlsafe_b64encode(b'{"iss":"example.com"}').rstrip(b"=")
        challenge["nonce"] = f"{header.decode()}.{payload.decode()}"
        with pytest.raises(ValueError):
            create_response(challenge, priv, "k")
        challenge["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA=="
        with pytest.raises(ValueError):
            create_response(challenge, priv, "k")
        challenge["nonce"] = "AAAAAAAAAAAAAAAAAAAAAB"
        with pytest.raises(ValueError):
            create_response(challenge, priv, "k")
        challenge["nonce"] = "AAAAAAAAAAAAAAAAAAAAAA"
        create_response(challenge, priv, "k")

    def test_response_signature_is_domain_separated_and_bound(self):
        from agentpin.crypto import verify_signature

        priv, pub = generate_key_pair()
        challenge = create_challenge("eyJ.verifier.jwt")
        response = create_response(challenge, priv, "k")
        assert verify_signature(pub, challenge["nonce"].encode(), response["signature"]) is False
        assert verify_response({**response, "kid": "other"}, challenge, pub) is False
        other_verifier = {**challenge, "verifier_credential": "eyJ.someone.else"}
        assert verify_response(response, other_verifier, pub) is False
