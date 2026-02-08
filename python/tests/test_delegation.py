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
