"""Tests for capability parsing and matching."""

from agentpin.capability import Capability, capabilities_hash, capabilities_subset


class TestCapabilityParse:
    def test_parses_action_resource(self):
        c = Capability("read:codebase")
        assert c.action == "read"
        assert c.resource == "codebase"


class TestCapabilityMatches:
    def test_wildcard(self):
        wild = Capability("read:*")
        assert wild.matches(Capability("read:codebase"))
        assert wild.matches(Capability("read:database"))
        assert not wild.matches(Capability("write:codebase"))

    def test_exact(self):
        cap = Capability("write:report")
        assert cap.matches(Capability("write:report"))
        assert not cap.matches(Capability("write:text"))

    def test_scoped(self):
        cap = Capability("read:codebase")
        assert cap.matches(Capability("read:codebase.github.com/org/repo"))
        assert not cap.matches(Capability("read:codebase_other"))


class TestCapabilitiesSubset:
    def test_valid_subset(self):
        declared = [Capability("read:*"), Capability("write:report")]
        requested = [Capability("read:codebase"), Capability("write:report")]
        assert capabilities_subset(declared, requested)

    def test_invalid_subset(self):
        declared = [Capability("read:*"), Capability("write:report")]
        requested = [Capability("delete:database")]
        assert not capabilities_subset(declared, requested)


class TestCapabilitiesHash:
    def test_deterministic(self):
        caps = [Capability("write:report"), Capability("read:codebase")]
        h1 = capabilities_hash(caps)
        h2 = capabilities_hash(caps)
        assert h1 == h2
        assert len(h1) == 64

    def test_order_independent(self):
        caps1 = [Capability("read:codebase"), Capability("write:report")]
        caps2 = [Capability("write:report"), Capability("read:codebase")]
        assert capabilities_hash(caps1) == capabilities_hash(caps2)
