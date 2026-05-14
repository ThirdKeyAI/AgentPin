"""Tests for capability parsing and matching."""

import pytest

from agentpin.capability import (
    CORE_ACTIONS,
    Capability,
    capabilities_hash,
    capabilities_subset,
    validate_capability,
)


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


class TestValidateCapability:
    def test_validate_core_action(self):
        validate_capability(Capability("read:codebase"))
        validate_capability(Capability("write:report"))
        validate_capability(Capability("execute:task"))

    def test_validate_wildcard(self):
        validate_capability(Capability("read:*"))
        validate_capability(Capability("write:*"))

    def test_validate_admin_wildcard_rejected(self):
        with pytest.raises(ValueError, match="admin:\\* wildcard is not allowed"):
            validate_capability(Capability("admin:*"))

    def test_validate_admin_scoped_ok(self):
        validate_capability(Capability("admin:users"))
        validate_capability(Capability("admin:config"))

    def test_validate_custom_action_with_domain(self):
        validate_capability(Capability("com.example.audit:logs"))
        validate_capability(Capability("org.acme.deploy:staging"))

    def test_validate_custom_action_without_domain(self):
        with pytest.raises(ValueError, match="reverse-domain prefix"):
            validate_capability(Capability("audit:logs"))

    def test_validate_missing_colon(self):
        with pytest.raises(ValueError, match="missing ':'"):
            validate_capability(Capability("readcodebase"))
