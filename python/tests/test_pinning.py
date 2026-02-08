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
