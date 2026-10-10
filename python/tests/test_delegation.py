"""Tests for delegation attestation."""

import pytest

from agentpin.capability import Capability
from agentpin.crypto import generate_key_pair
from agentpin.delegation import create_attestation, verify_attestation, verify_chain_depth
from agentpin.types import AgentPinError, DelegationRole


class TestAttestationRoundtrip:
    def test_create_and_verify(self):
        priv, pub = generate_key_pair()
        caps = [Capability("read:data"), Capability("write:report")]

        att = create_attestation(
            priv,
            "maker-2026-01",
            "maker.com",
            DelegationRole.MAKER,
            "urn:agentpin:maker.com:agent-type",
            "deployer.com",
            "urn:agentpin:deployer.com:instance",
            caps,
        )

        assert att["domain"] == "maker.com"
        assert att["role"] == DelegationRole.MAKER

        verify_attestation(att, pub, "deployer.com", "urn:agentpin:deployer.com:instance", caps)

    def test_wrong_key_rejected(self):
        priv1, _ = generate_key_pair()
        _, pub2 = generate_key_pair()
        caps = [Capability("read:data")]

        att = create_attestation(
            priv1, "kid", "domain", DelegationRole.MAKER, "agent", "delegatee", "delegatee-agent", caps
        )

        with pytest.raises(AgentPinError, match="failed"):
            verify_attestation(att, pub2, "delegatee", "delegatee-agent", caps)

    def test_wrong_capabilities_rejected(self):
        priv, pub = generate_key_pair()
        caps = [Capability("read:data")]
        wrong_caps = [Capability("write:data")]

        att = create_attestation(
            priv, "kid", "domain", DelegationRole.MAKER, "agent", "delegatee", "delegatee-agent", caps
        )

        with pytest.raises(AgentPinError, match="failed"):
            verify_attestation(att, pub, "delegatee", "delegatee-agent", wrong_caps)


class TestVerifyChainDepth:
    def test_within_depth(self):
        verify_chain_depth(1, [2, 3])
        verify_chain_depth(2, [2, 3])

    def test_exceeding_depth(self):
        with pytest.raises(AgentPinError, match="exceeds"):
            verify_chain_depth(3, [2, 3])


class TestAttestationBinding:
    """Design issue 7 / AP-1 regression tests."""

    def test_bound_to_kid(self):
        priv, pub = generate_key_pair()
        caps = [Capability("read:data")]
        att = create_attestation(priv, "kid-1", "maker.com", DelegationRole.MAKER, "a", "deployer.com", "da", caps)
        att["kid"] = "kid-2"
        with pytest.raises(AgentPinError, match="failed"):
            verify_attestation(att, pub, "deployer.com", "da", caps)

    def test_expiry_enforced_and_signed(self):
        import time

        priv, pub = generate_key_pair()
        caps = [Capability("read:data")]
        now = int(time.time())
        fresh = create_attestation(
            priv, "k", "maker.com", DelegationRole.MAKER, "a", "deployer.com", "da", caps, exp=now + 3600
        )
        verify_attestation(fresh, pub, "deployer.com", "da", caps)
        expired = create_attestation(
            priv, "k", "maker.com", DelegationRole.MAKER, "a", "deployer.com", "da", caps, exp=now - 10
        )
        with pytest.raises(AgentPinError, match="expired"):
            verify_attestation(expired, pub, "deployer.com", "da", caps)
        stripped = {k: v for k, v in fresh.items() if k != "exp"}
        with pytest.raises(AgentPinError, match="failed"):
            verify_attestation(stripped, pub, "deployer.com", "da", caps)

    def test_legacy_pipe_format_rejected(self):
        from agentpin.capability import capabilities_hash
        from agentpin.crypto import sign_data

        priv, pub = generate_key_pair()
        caps = [Capability("read:data")]
        legacy = f"maker.com|maker|a|deployer.com|da|{capabilities_hash(caps)}"
        att = {
            "domain": "maker.com",
            "role": "maker",
            "agent_id": "a",
            "kid": "k",
            "attestation": sign_data(priv, legacy.encode()),
        }
        with pytest.raises(AgentPinError, match="failed"):
            verify_attestation(att, pub, "deployer.com", "da", caps)

    def test_chain_depth_empty_list_is_zero(self):
        with pytest.raises(AgentPinError, match="exceeds"):
            verify_chain_depth(1, [])
