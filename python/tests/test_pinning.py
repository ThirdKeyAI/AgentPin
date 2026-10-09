"""Tests for TOFU key pinning."""

import pytest

from agentpin.pinning import KeyPinStore, PinningResult, check_pinning
from agentpin.types import AgentPinError


def make_test_jwk(kid, x):
    return {
        "kid": kid,
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": "test-y",
        "use": "sig",
    }


class TestKeyPinStore:
    def test_first_use_pins(self):
        store = KeyPinStore()
        jwk = make_test_jwk("key-1", "x-value-1")
        result = store.check_and_pin("example.com", jwk)
        assert result == PinningResult.FIRST_USE

        result = store.check_and_pin("example.com", jwk)
        assert result == PinningResult.MATCHED

    def test_key_change_detected(self):
        store = KeyPinStore()
        jwk1 = make_test_jwk("key-1", "x-value-1")
        store.check_and_pin("example.com", jwk1)

        jwk2 = make_test_jwk("key-2", "x-value-2")
        result = store.check_and_pin("example.com", jwk2)
        assert result == PinningResult.CHANGED

    def test_add_key_allows_rotation(self):
        store = KeyPinStore()
        jwk1 = make_test_jwk("key-1", "x-value-1")
        store.check_and_pin("example.com", jwk1)

        jwk2 = make_test_jwk("key-2", "x-value-2")
        store.add_key("example.com", jwk2)

        assert store.check_and_pin("example.com", jwk1) == PinningResult.MATCHED
        assert store.check_and_pin("example.com", jwk2) == PinningResult.MATCHED

    def test_json_roundtrip(self):
        store = KeyPinStore()
        jwk = make_test_jwk("key-1", "x-value-1")
        store.check_and_pin("example.com", jwk)

        json_str = store.to_json()
        store2 = KeyPinStore.from_json(json_str)
        assert store2.get_domain("example.com") is not None
        assert len(store2.get_domain("example.com")["pinned_keys"]) == 1

    def test_different_domains_independent(self):
        store = KeyPinStore()
        jwk1 = make_test_jwk("key-1", "x-value-1")
        jwk2 = make_test_jwk("key-2", "x-value-2")

        store.check_and_pin("a.com", jwk1)
        store.check_and_pin("b.com", jwk2)

        assert store.check_and_pin("a.com", jwk1) == PinningResult.MATCHED
        assert store.check_and_pin("b.com", jwk2) == PinningResult.MATCHED
        assert store.check_and_pin("a.com", jwk2) == PinningResult.CHANGED


class TestCheckPinning:
    def test_throws_on_change(self):
        store = KeyPinStore()
        jwk1 = make_test_jwk("key-1", "x-value-1")
        store.check_and_pin("example.com", jwk1)

        jwk2 = make_test_jwk("key-2", "x-value-2")
        with pytest.raises(AgentPinError, match="changed"):
            check_pinning(store, "example.com", jwk2)


def test_pin_key_normalized():
    """AP-3: pins are keyed on the normalized domain."""
    from agentpin.pinning import KeyPinStore, PinningResult

    store = KeyPinStore()
    j1 = {"kid": "k1", "kty": "EC", "crv": "P-256", "x": "x1", "y": "y"}
    j2 = {"kid": "k2", "kty": "EC", "crv": "P-256", "x": "x2", "y": "y"}
    assert store.check_and_pin("example.com", j1) == PinningResult.FIRST_USE
    assert store.check_and_pin("EXAMPLE.COM", j1) == PinningResult.MATCHED
    assert store.check_and_pin("Example.Com.", j2) == PinningResult.CHANGED
    assert store.get_domain("EXAMPLE.COM") is not None
    loaded = KeyPinStore.from_json(
        '[{"domain":"EXAMPLE.COM","pinned_keys":[{"kid":"k","public_key_hash":"h1","first_seen":"t",'
        '"last_seen":"t","trust_level":"tofu"}]},'
        '{"domain":"example.com","pinned_keys":[{"kid":"k2","public_key_hash":"h2","first_seen":"t",'
        '"last_seen":"t","trust_level":"tofu"}]}]'
    )
    assert len(loaded.get_domain("example.com")["pinned_keys"]) == 2
