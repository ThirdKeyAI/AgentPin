"""Tests for ECDSA P-256 cryptographic operations."""

from agentpin.crypto import (
    generate_key_id,
    generate_key_pair,
    sha256_hash,
    sha256_hex,
    sign_data,
    verify_signature,
)


class TestGenerateKeyPair:
    def test_generates_pem_keypair(self):
        priv, pub = generate_key_pair()
        assert priv.startswith("-----BEGIN PRIVATE KEY-----")
        assert pub.startswith("-----BEGIN PUBLIC KEY-----")


class TestSignAndVerify:
    def test_roundtrip(self):
        priv, pub = generate_key_pair()
        data = b"hello agentpin"
        sig = sign_data(priv, data)
        assert verify_signature(pub, data, sig)

    def test_wrong_data_fails(self):
        priv, pub = generate_key_pair()
        data = b"hello agentpin"
        sig = sign_data(priv, data)
        assert not verify_signature(pub, b"wrong data", sig)

    def test_wrong_key_fails(self):
        priv1, _ = generate_key_pair()
        _, pub2 = generate_key_pair()
        data = b"test data"
        sig = sign_data(priv1, data)
        assert not verify_signature(pub2, data, sig)


class TestGenerateKeyId:
    def test_64_hex_chars(self):
        _, pub = generate_key_pair()
        kid = generate_key_id(pub)
        assert len(kid) == 64

    def test_deterministic(self):
        _, pub = generate_key_pair()
        kid1 = generate_key_id(pub)
        kid2 = generate_key_id(pub)
        assert kid1 == kid2


class TestSha256:
    def test_known_hash(self):
        h = sha256_hex(b"test")
        assert len(h) == 64
        assert h == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    def test_returns_bytes(self):
        h = sha256_hash(b"test")
        assert isinstance(h, bytes)
        assert len(h) == 32
