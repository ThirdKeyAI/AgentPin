"""Tests for credential verification (12-step flow)."""

import pytest

from agentpin.capability import Capability
from agentpin.credential import issue_credential
from agentpin.crypto import generate_key_pair
from agentpin.discovery import build_discovery_document
from agentpin.jwk import pem_to_jwk
from agentpin.jwt import decode_jwt_unverified, encode_jwt
from agentpin.pinning import KeyPinStore
from agentpin.revocation import add_revoked_agent, add_revoked_credential, build_revocation_document
from agentpin.types import (
    AgentStatus,
    DataClassification,
    EntityType,
    ErrorCode,
    RevocationReason,
    VerifierConfig,
)
from agentpin.verification import verify_credential_offline


def setup():
    priv, pub = generate_key_pair()
    jwk = pem_to_jwk(pub, "test-2026-01")

    discovery = build_discovery_document(
        "example.com",
        EntityType.MAKER,
        [jwk],
        [
            {
                "agent_id": "urn:agentpin:example.com:agent",
                "name": "Test Agent",
                "capabilities": ["read:*", "write:report"],
                "constraints": {
                    "data_classification_max": DataClassification.CONFIDENTIAL,
                    "rate_limit": "100/hour",
                },
                "status": AgentStatus.ACTIVE,
            }
        ],
        2,
        "2026-01-15T00:00:00Z",
    )

    jwt_str = issue_credential(
        priv,
        "test-2026-01",
        "example.com",
        "urn:agentpin:example.com:agent",
        "verifier.com",
        [Capability("read:data"), Capability("write:report")],
        {
            "data_classification_max": DataClassification.INTERNAL,
            "rate_limit": "50/hour",
        },
        None,
        3600,
    )

    return {
        "priv": priv,
        "pub": pub,
        "jwt": jwt_str,
        "discovery": discovery,
        "revocation": build_revocation_document("example.com"),
        "pin_store": KeyPinStore(),
        "config": VerifierConfig(),
    }


class TestVerifyCredentialOffline:
    def test_happy_path(self):
        f = setup()
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert result.valid, f"Expected valid, got: {result}"
        assert result.agent_id == "urn:agentpin:example.com:agent"
        assert result.issuer == "example.com"

    def test_expired_credential(self):
        f = setup()
        header = {"alg": "ES256", "typ": "agentpin-credential+jwt", "kid": "test-2026-01"}
        payload = {
            "iss": "example.com",
            "sub": "urn:agentpin:example.com:agent",
            "iat": 1000000,
            "exp": 1003600,
            "jti": "expired-jti",
            "agentpin_version": "0.1",
            "capabilities": ["read:data"],
        }
        expired_jwt = encode_jwt(header, payload, f["priv"])
        result = verify_credential_offline(
            expired_jwt, f["discovery"], None, KeyPinStore(), None, f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CREDENTIAL_EXPIRED

    def test_wrong_algorithm_rejected(self):
        f = setup()
        result = verify_credential_offline(
            "invalid.jwt.token", f["discovery"], None, KeyPinStore(), None, f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.ALGORITHM_REJECTED

    def test_credential_revoked(self):
        f = setup()
        _, payload, _ = decode_jwt_unverified(f["jwt"])
        add_revoked_credential(f["revocation"], payload["jti"], RevocationReason.KEY_COMPROMISE)
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CREDENTIAL_REVOKED

    def test_agent_revoked(self):
        f = setup()
        add_revoked_agent(
            f["revocation"], "urn:agentpin:example.com:agent", RevocationReason.PRIVILEGE_WITHDRAWN
        )
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid

    def test_inactive_agent(self):
        f = setup()
        f["discovery"]["agents"][0]["status"] = AgentStatus.SUSPENDED
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.AGENT_INACTIVE

    def test_capability_exceeded(self):
        f = setup()
        f["discovery"]["agents"][0]["capabilities"] = ["read:limited"]
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.CAPABILITY_EXCEEDED

    def test_audience_mismatch(self):
        f = setup()
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "wrong-verifier.com", f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.AUDIENCE_MISMATCH

    def test_key_pin_change_rejected(self):
        f = setup()
        # First verification pins
        result1 = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert result1.valid

        # Change key
        priv2, pub2 = generate_key_pair()
        jwk2 = pem_to_jwk(pub2, "test-2026-01")
        f["discovery"]["public_keys"] = [jwk2]

        jwt2 = issue_credential(
            priv2, "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 3600,
        )

        result2 = verify_credential_offline(
            jwt2, f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert not result2.valid
        assert result2.error_code == ErrorCode.KEY_PIN_MISMATCH

    def test_key_rotation_with_continuity_accepted(self):
        f = setup()
        assert verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        ).valid
        priv2, pub2 = generate_key_pair()
        f["discovery"]["public_keys"] = f["discovery"]["public_keys"] + [pem_to_jwk(pub2, "test-2026-02")]
        jwt2 = issue_credential(
            priv2, "test-2026-02", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 3600,
        )
        r2 = verify_credential_offline(jwt2, f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"])
        assert r2.valid, r2
        assert r2.key_pinning["status"] == "rotated"
        f["discovery"]["public_keys"] = f["discovery"]["public_keys"][1:]
        r3 = verify_credential_offline(jwt2, f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"])
        assert r3.valid
        assert r3.key_pinning["status"] == "pinned"

    def test_domain_mismatch(self):
        f = setup()
        f["discovery"]["entity"] = "other.com"
        result = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], None, f["config"]
        )
        assert not result.valid
        assert result.error_code == ErrorCode.DISCOVERY_INVALID

    def test_wildcard_audience_accepted(self):
        priv, pub = generate_key_pair()
        jwk = pem_to_jwk(pub, "test-key")

        discovery = build_discovery_document(
            "example.com",
            EntityType.MAKER,
            [jwk],
            [
                {
                    "agent_id": "urn:agentpin:example.com:agent",
                    "name": "Test",
                    "capabilities": ["read:*"],
                    "status": AgentStatus.ACTIVE,
                }
            ],
            2,
            "2026-01-15T00:00:00Z",
        )

        jwt_str = issue_credential(
            priv, "test-key", "example.com", "urn:agentpin:example.com:agent",
            "*", [Capability("read:data")], None, None, 3600,
        )

        result = verify_credential_offline(
            jwt_str, discovery, None, KeyPinStore(), "any-verifier.com", VerifierConfig()
        )
        assert result.valid, "Wildcard audience should be accepted"


class TestIssuerNormalization:
    """AP-3 / AP-10 / AP-12 regression tests."""

    def test_case_variant_iss_hits_existing_pin(self):
        f = setup()
        r1 = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert r1.valid, r1
        priv2, pub2 = generate_key_pair()
        evil = dict(f["discovery"], entity="EXAMPLE.COM", public_keys=[pem_to_jwk(pub2, "evil-key")])
        evil_jwt = issue_credential(
            priv2, "evil-key", "EXAMPLE.COM", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 3600,
        )
        r2 = verify_credential_offline(evil_jwt, evil, None, f["pin_store"], "verifier.com", f["config"])
        assert not r2.valid
        assert r2.error_code == ErrorCode.KEY_PIN_MISMATCH
        assert len(f["pin_store"].get_domain("example.com")["pinned_keys"]) == 1

    def test_issuer_entity_compared_normalized(self):
        f = setup()
        f["discovery"]["entity"] = "Example.COM."
        r = verify_credential_offline(
            f["jwt"], f["discovery"], f["revocation"], f["pin_store"], "verifier.com", f["config"]
        )
        assert r.valid, r
        assert r.issuer == "example.com"

    @pytest.mark.parametrize(
        "bad_iss", ["127.0.0.1:8443", "../../tmp/x", "/srv/uploads/x", "example.com/path", "user@example.com"]
    )
    def test_non_hostname_iss_rejected(self, bad_iss):
        f = setup()
        jwt_str = issue_credential(
            f["priv"], "test-2026-01", bad_iss, "urn:agentpin:example.com:agent",
            None, [Capability("read:data")], None, None, 3600,
        )
        r = verify_credential_offline(jwt_str, f["discovery"], None, KeyPinStore(), None, f["config"])
        assert not r.valid
        assert r.error_code == ErrorCode.DISCOVERY_INVALID


class TestRevocationDocumentValidation:
    """Design issue 3: foreign, tampered, unsigned-under-strict and stale documents fail closed."""

    def test_validation(self):
        from datetime import datetime, timedelta, timezone

        from agentpin.revocation import sign_revocation_document

        f = setup()

        def run(rev, cfg):
            return verify_credential_offline(f["jwt"], f["discovery"], rev, KeyPinStore(), "verifier.com", cfg)

        assert run(dict(f["revocation"], entity="other.com"), f["config"]).error_code == ErrorCode.DISCOVERY_INVALID
        strict = VerifierConfig(require_signed_revocation=True)
        assert run(f["revocation"], strict).error_code == ErrorCode.DISCOVERY_INVALID
        signed = sign_revocation_document(dict(f["revocation"]), f["priv"], "test-2026-01")
        assert run(signed, strict).valid
        assert run(dict(signed, updated_at="2030-01-01T00:00:00Z"), f["config"]).error_code == ErrorCode.DISCOVERY_INVALID
        aged = VerifierConfig(revocation_max_age_secs=60)
        stale = dict(f["revocation"], updated_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
        assert run(stale, aged).error_code == ErrorCode.DISCOVERY_INVALID
        assert run(f["revocation"], aged).valid


def _raw_credential(priv, payload_json: str) -> str:
    import base64

    from agentpin.crypto import sign_data

    header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"test-2026-01"}').rstrip(b"=")
    signing_input = header.decode() + "." + base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
    der = base64.b64decode(sign_data(priv, signing_input.encode()))
    return signing_input + "." + base64.urlsafe_b64encode(der).rstrip(b"=").decode()


class TestClaimValidation:
    """AP-5 / AP-14 / AP-18 regression tests."""

    @pytest.mark.parametrize(
        "payload_tpl",
        [
            '{{{base},"iat":{now}}}',
            '{{{base},"iat":{now},"exp":"never"}}',
            '{{{base},"iat":{now},"exp":{{}}}}',
            '{{{base},"iat":-9223372036854775808,"exp":{far}}}',
            '{{{base},"iat":{now},"exp":{now}}}',
            '{{{base},"iat":{now},"exp":true}}',
            "null",
            "[]",
        ],
    )
    def test_malformed_claims_return_failure_not_exception(self, payload_tpl):
        import time

        f = setup()
        now = int(time.time())
        base = (
            '"iss":"example.com","sub":"urn:agentpin:example.com:agent","jti":"j",'
            '"agentpin_version":"0.1","capabilities":["read:data"]'
        )
        payload = payload_tpl.format(base=base, now=now, far=now + 315360000)
        r = verify_credential_offline(_raw_credential(f["priv"], payload), f["discovery"], None, KeyPinStore(), None)
        assert not r.valid
        assert r.error_code == ErrorCode.MALFORMED_CREDENTIAL

    def test_missing_kid_or_non_object_header_does_not_raise(self):
        import base64

        f = setup()
        header = base64.urlsafe_b64encode(b'{"alg":"ES256","typ":"agentpin-credential+jwt"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"iss":"example.com"}').rstrip(b"=").decode()
        r = verify_credential_offline(f"{header}.{payload}.sig", f["discovery"], None, KeyPinStore(), None)
        assert not r.valid
        assert r.error_code == ErrorCode.MALFORMED_CREDENTIAL
        null_header = base64.urlsafe_b64encode(b"null").rstrip(b"=").decode()
        r2 = verify_credential_offline(f"{null_header}.{payload}.sig", f["discovery"], None, KeyPinStore(), None)
        assert not r2.valid

    def test_credential_ttl_max_enforced(self):
        f = setup()
        f["discovery"]["agents"][0]["credential_ttl_max"] = 600
        long = issue_credential(
            f["priv"], "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 3600,
        )
        r = verify_credential_offline(long, f["discovery"], None, KeyPinStore(), "verifier.com")
        assert r.error_code == ErrorCode.CREDENTIAL_EXPIRED
        assert "credential_ttl_max" in r.error_message
        short = issue_credential(
            f["priv"], "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 600,
        )
        assert verify_credential_offline(short, f["discovery"], None, KeyPinStore(), "verifier.com").valid
        del f["discovery"]["agents"][0]["credential_ttl_max"]
        two_days = issue_credential(
            f["priv"], "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability("read:data")], None, None, 172800,
        )
        lax = VerifierConfig(max_ttl_secs=10 * 86400)
        assert (
            verify_credential_offline(two_days, f["discovery"], None, KeyPinStore(), "verifier.com", lax).error_code
            == ErrorCode.CREDENTIAL_EXPIRED
        )


def test_revocation_document_with_wrong_field_names_fails_closed():
    """AP-8: the schema the old docs published must fail closed, not crash or be ignored."""
    f = setup()
    _, payload, _ = decode_jwt_unverified(f["jwt"])
    wrong = {
        "agentpin_version": "0.1",
        "entity": "example.com",
        "revoked_credentials": [{"id": payload["jti"], "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z"}],
        "revoked_agents": [],
        "revoked_keys": [{"id": "test-2026-01", "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z"}],
        "updated_at": "2026-02-15T00:00:00Z",
    }
    r = verify_credential_offline(f["jwt"], f["discovery"], wrong, KeyPinStore(), "verifier.com")
    assert not r.valid
    assert r.error_code == ErrorCode.DISCOVERY_INVALID


def test_check_revocation_tolerates_malformed_entries_without_raising():
    from agentpin.revocation import check_revocation

    check_revocation({"revoked_credentials": [None, "x", {"id": "j"}], "revoked_keys": None}, "j", "a", "k")


def test_omitted_constraints_inherit_discovery_defaults():
    """AP-15: the result carries the effective (merged) constraints; widening is rejected."""
    f = setup()
    f["discovery"]["agents"][0]["constraints"] = {"allowed_domains": ["*.client-corp.com"], "rate_limit": "100/hour"}
    jwt_str = issue_credential(
        f["priv"], "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
        "verifier.com", [Capability("read:data")], None, None, 3600,
    )
    r = verify_credential_offline(jwt_str, f["discovery"], None, KeyPinStore(), "verifier.com")
    assert r.valid, r
    assert r.constraints["allowed_domains"] == ["*.client-corp.com"]
    assert r.constraints["rate_limit"] == "100/hour"
    wide = issue_credential(
        f["priv"], "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
        "verifier.com", [Capability("read:data")], {"allowed_domains": ["evil.com"]}, None, 3600,
    )
    assert (
        verify_credential_offline(wide, f["discovery"], None, KeyPinStore(), "verifier.com").error_code
        == ErrorCode.CONSTRAINT_VIOLATION
    )


def _delegation_fixture():
    from agentpin.delegation import create_attestation
    from agentpin.types import DelegationRole

    maker_priv, maker_pub = generate_key_pair()
    maker_doc = build_discovery_document(
        "maker.com", EntityType.MAKER, [pem_to_jwk(maker_pub, "maker-2026-01")],
        [{"agent_id": "urn:agentpin:maker.com:agent-type", "name": "Agent Type", "capabilities": ["read:*"],
          "status": AgentStatus.ACTIVE}],
        2, "2026-01-15T00:00:00Z",
    )
    dep_priv, dep_pub = generate_key_pair()
    dep_doc = build_discovery_document(
        "example.com", EntityType.DEPLOYER, [pem_to_jwk(dep_pub, "deployer-2026-01")],
        [{"agent_id": "urn:agentpin:example.com:agent", "agent_type": "urn:agentpin:maker.com:agent-type",
          "name": "Deployed", "capabilities": ["read:*"], "status": AgentStatus.ACTIVE}],
        2, "2026-01-15T00:00:00Z",
    )
    caps = [Capability("read:data")]
    att = create_attestation(
        maker_priv, "maker-2026-01", "maker.com", DelegationRole.MAKER,
        "urn:agentpin:maker.com:agent-type", "example.com", "urn:agentpin:example.com:agent", caps,
    )
    jwt_str = issue_credential(
        dep_priv, "deployer-2026-01", "example.com", "urn:agentpin:example.com:agent",
        "verifier.com", caps, None, [att], 3600,
    )

    class _Resolver:
        def __init__(self, *docs):
            self.docs = docs

        def resolve_discovery(self, domain):
            for d in self.docs:
                if d["entity"] == domain:
                    return d
            raise RuntimeError(f"no doc for {domain}")

    return {"jwt": jwt_str, "maker_doc": maker_doc, "dep_doc": dep_doc, "dep_priv": dep_priv, "caps": caps,
            "resolver": _Resolver}


class TestDelegationChain:
    """AP-2 regression tests."""

    def test_genuine_chain_verifies(self):
        f = _delegation_fixture()
        r = verify_credential_offline(
            f["jwt"], f["dep_doc"], None, KeyPinStore(), "verifier.com", chain_resolver=f["resolver"](f["maker_doc"])
        )
        assert r.valid, r
        assert r.delegation_verified is True
        assert r.delegation_chain == [{"domain": "maker.com", "role": "maker", "verified": True}]
        assert r.warnings == []

    def test_forged_attestation_rejected_and_unverifiable_fails_closed(self):
        f = _delegation_fixture()
        forged = issue_credential(
            f["dep_priv"], "deployer-2026-01", "example.com", "urn:agentpin:example.com:agent", "verifier.com",
            f["caps"], None,
            [{"domain": "maker.com", "role": "maker", "agent_id": "urn:agentpin:maker.com:agent-type",
              "kid": "maker-2026-01", "attestation": "AAAA"}],
            3600,
        )
        r1 = verify_credential_offline(
            forged, f["dep_doc"], None, KeyPinStore(), "verifier.com", chain_resolver=f["resolver"](f["maker_doc"])
        )
        assert not r1.valid
        assert r1.error_code == ErrorCode.DELEGATION_INVALID
        r2 = verify_credential_offline(f["jwt"], f["dep_doc"], None, KeyPinStore(), "verifier.com")
        assert not r2.valid
        assert r2.error_code == ErrorCode.DELEGATION_INVALID
        lax = VerifierConfig(require_delegation_verification=False)
        r3 = verify_credential_offline(f["jwt"], f["dep_doc"], None, KeyPinStore(), "verifier.com", lax)
        assert r3.valid
        assert r3.delegation_verified is False
        assert r3.warnings

    def test_failure_modes(self):
        f = _delegation_fixture()

        def run(doc):
            return verify_credential_offline(
                f["jwt"], f["dep_doc"], None, KeyPinStore(), "verifier.com", chain_resolver=f["resolver"](doc)
            )

        assert run({"entity": "other.com"}).error_code == ErrorCode.DELEGATION_INVALID
        no_key = dict(f["maker_doc"], public_keys=[dict(f["maker_doc"]["public_keys"][0], kid="maker-2026-02")])
        assert run(no_key).error_code == ErrorCode.DELEGATION_INVALID
        assert run(dict(f["maker_doc"], max_delegation_depth=0)).error_code == ErrorCode.DELEGATION_DEPTH_EXCEEDED
        narrow = dict(f["maker_doc"], agents=[dict(f["maker_doc"]["agents"][0], capabilities=["read:public"])])
        r = run(narrow)
        assert r.error_code == ErrorCode.DELEGATION_INVALID and "exceed" in r.error_message
        suspended = dict(f["maker_doc"], agents=[dict(f["maker_doc"]["agents"][0], status="suspended")])
        assert run(suspended).error_code == ErrorCode.DELEGATION_INVALID

    def test_bundle_verification_verifies_chain(self):
        from agentpin.bundle import create_trust_bundle, verify_credential_with_bundle

        f = _delegation_fixture()
        bundle = create_trust_bundle()
        bundle["documents"] = [f["dep_doc"], f["maker_doc"]]
        r = verify_credential_with_bundle(f["jwt"], bundle, KeyPinStore(), "verifier.com")
        assert r.valid, r
        assert r.delegation_verified is True


def test_key_metadata_enforced():
    """AP-20 / AP-21: unparsable exp, use != sig, key_ops without verify are rejected."""
    f = setup()

    def run(**mutate):
        doc = dict(f["discovery"], public_keys=[dict(f["discovery"]["public_keys"][0], **mutate)])
        return verify_credential_offline(f["jwt"], doc, None, KeyPinStore(), "verifier.com")

    assert run(exp="expired").error_code == ErrorCode.KEY_EXPIRED
    assert run(exp="2020-01-01T00:00:00Z").error_code == ErrorCode.KEY_EXPIRED
    assert run(use="enc").error_code == ErrorCode.KEY_NOT_FOUND
    assert run(key_ops=["sign"]).error_code == ErrorCode.KEY_NOT_FOUND
    assert run(exp="2099-01-01T00:00:00Z").valid


def test_capability_taxonomy_enforced():
    """AP-21: admin:* is never accepted; strict mode rejects non-reverse-domain custom actions."""
    f = setup()

    def issue(*caps):
        return issue_credential(
            f["priv"], "test-2026-01", "example.com", "urn:agentpin:example.com:agent",
            "verifier.com", [Capability(c) for c in caps], None, None, 3600,
        )

    admin = dict(f["discovery"], agents=[dict(f["discovery"]["agents"][0], capabilities=["admin:*"])])
    lax = VerifierConfig(strict_capabilities=False)
    for cfg in (f["config"], lax):
        r = verify_credential_offline(issue("admin:*"), admin, None, KeyPinStore(), "verifier.com", cfg)
        assert r.error_code == ErrorCode.CAPABILITY_EXCEEDED
    custom = dict(f["discovery"], agents=[dict(f["discovery"]["agents"][0], capabilities=["scan:target", "com.example.scan:target"])])
    r = verify_credential_offline(issue("scan:target"), custom, None, KeyPinStore(), "verifier.com", f["config"])
    assert r.error_code == ErrorCode.CAPABILITY_EXCEEDED
    assert verify_credential_offline(issue("scan:target"), custom, None, KeyPinStore(), "verifier.com", lax).valid
    rev = dict(f["discovery"], agents=[dict(f["discovery"]["agents"][0], capabilities=["com.example.scan:target"])])
    assert verify_credential_offline(issue("com.example.scan:target"), rev, None, KeyPinStore(), "verifier.com", f["config"]).valid
