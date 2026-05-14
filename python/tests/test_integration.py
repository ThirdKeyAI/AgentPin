"""End-to-end integration tests for AgentPin."""

import json

import pytest

from agentpin import (
    KeyPinStore,
    PinningResult,
    VerifierConfig,
    build_discovery_document,
    build_revocation_document,
    add_revoked_key,
    check_pinning,
    check_revocation,
    create_challenge,
    create_response,
    generate_key_id,
    generate_key_pair,
    issue_credential,
    pem_to_jwk,
    decode_jwt_unverified,
    verify_jwt,
    verify_credential_offline,
    verify_response_with_nonce_store,
    http_extract_credential,
    http_format_authorization_header,
    mcp_extract_credential,
    mcp_format_meta_field,
    ws_extract_credential,
    ws_format_auth_message,
    grpc_extract_credential,
    grpc_format_metadata_value,
    apply_rotation,
    complete_rotation,
    prepare_rotation,
    AgentPinError,
)
from agentpin.nonce import InMemoryNonceStore


def make_test_setup():
    """Create a keypair, kid, JWK, and discovery document for testing."""
    private_pem, public_pem = generate_key_pair()
    kid = generate_key_id(public_pem)
    jwk = pem_to_jwk(public_pem, kid)
    agent_id = "urn:agentpin:example.com:test-agent"
    doc = build_discovery_document(
        entity="example.com",
        entity_type="maker",
        public_keys=[jwk],
        agents=[
            {
                "agent_id": agent_id,
                "name": "Test Agent",
                "capabilities": ["read:*", "write:report"],
                "status": "active",
                "credential_ttl_max": 3600,
            }
        ],
        max_delegation_depth=2,
        updated_at="2026-01-01T00:00:00Z",
    )
    return private_pem, public_pem, kid, agent_id, doc


class TestMakerDeployerFlow:
    def test_full_credential_lifecycle(self):
        private_pem, public_pem, kid, agent_id, doc = make_test_setup()

        # Issue a credential
        jwt_str = issue_credential(
            private_key_pem=private_pem,
            kid=kid,
            issuer="example.com",
            agent_id=agent_id,
            audience="verifier.com",
            capabilities=["read:data", "write:report"],
            constraints=None,
            delegation_chain=None,
            ttl_secs=3600,
        )
        assert jwt_str
        assert jwt_str.count(".") == 2

        # Decode unverified to inspect
        header, payload, _sig = decode_jwt_unverified(jwt_str)
        assert header["alg"] == "ES256"
        assert header["typ"] == "agentpin-credential+jwt"
        assert header["kid"] == kid
        assert payload["iss"] == "example.com"
        assert payload["sub"] == agent_id

        # Verify signature
        verified_header, verified_payload = verify_jwt(jwt_str, public_pem)
        assert verified_header["kid"] == kid
        assert verified_payload["iss"] == "example.com"

        # Full offline verification
        pin_store = KeyPinStore()
        config = VerifierConfig()
        result = verify_credential_offline(
            jwt_str, doc, None, pin_store, "verifier.com", config
        )
        assert result.valid, f"Expected valid, got: {result.error_message}"
        assert result.agent_id == agent_id
        assert result.issuer == "example.com"


class TestRevocationFlow:
    def test_revoked_key_detected(self):
        private_pem, _public_pem, kid, agent_id, doc = make_test_setup()

        jwt_str = issue_credential(
            private_key_pem=private_pem,
            kid=kid,
            issuer="example.com",
            agent_id=agent_id,
            audience=None,
            capabilities=["read:data"],
            constraints=None,
            delegation_chain=None,
            ttl_secs=3600,
        )

        header, payload, _sig = decode_jwt_unverified(jwt_str)

        # Clean revocation: should pass
        rev_doc = build_revocation_document("example.com")
        check_revocation(rev_doc, payload["jti"], agent_id, kid)  # no error

        # Add revoked key
        add_revoked_key(rev_doc, kid, "key_compromise")

        # Now check_revocation should fail
        with pytest.raises(AgentPinError):
            check_revocation(rev_doc, payload["jti"], agent_id, kid)

        # Full offline verification should also fail
        pin_store = KeyPinStore()
        config = VerifierConfig()
        vresult = verify_credential_offline(
            jwt_str, doc, rev_doc, pin_store, None, config
        )
        assert not vresult.valid


class TestMutualVerificationWithNonceStore:
    def test_nonce_replay_prevention(self):
        private_pem, public_pem = generate_key_pair()

        store = InMemoryNonceStore()
        challenge = create_challenge()
        response = create_response(challenge, private_pem, "test-key")

        # First verification should succeed
        valid = verify_response_with_nonce_store(
            response, challenge, public_pem, store
        )
        assert valid

        # Second verification with same nonce should fail (replay)
        with pytest.raises(ValueError, match="already been used"):
            verify_response_with_nonce_store(
                response, challenge, public_pem, store
            )


class TestTransportRoundtrip:
    def test_all_transports(self):
        private_pem, _public_pem = generate_key_pair()
        kid = generate_key_id(_public_pem)

        jwt_str = issue_credential(
            private_key_pem=private_pem,
            kid=kid,
            issuer="example.com",
            agent_id="urn:agentpin:example.com:test-agent",
            audience=None,
            capabilities=["read:data"],
            constraints=None,
            delegation_chain=None,
            ttl_secs=3600,
        )

        # HTTP roundtrip
        http_header = http_format_authorization_header(jwt_str)
        http_extracted = http_extract_credential(http_header)
        assert http_extracted == jwt_str

        # MCP roundtrip
        mcp_meta = mcp_format_meta_field(jwt_str)
        mcp_extracted = mcp_extract_credential(mcp_meta)
        assert mcp_extracted == jwt_str

        # WebSocket roundtrip
        ws_msg = ws_format_auth_message(jwt_str)
        ws_extracted = ws_extract_credential(ws_msg)
        assert ws_extracted == jwt_str

        # gRPC roundtrip
        grpc_val = grpc_format_metadata_value(jwt_str)
        grpc_extracted = grpc_extract_credential(grpc_val)
        assert grpc_extracted == jwt_str


class TestKeyRotationLifecycle:
    def test_rotation_add_and_remove(self):
        private_pem, public_pem = generate_key_pair()
        old_kid = generate_key_id(public_pem)
        old_jwk = pem_to_jwk(public_pem, old_kid)

        doc = build_discovery_document(
            entity="example.com",
            entity_type="maker",
            public_keys=[old_jwk],
            agents=[],
            max_delegation_depth=2,
            updated_at="2026-01-01T00:00:00Z",
        )
        assert len(doc["public_keys"]) == 1

        # Prepare rotation
        plan = prepare_rotation(old_kid)
        assert plan["new_kid"] != old_kid

        # Apply rotation: both keys should be present
        apply_rotation(doc, plan)
        assert len(doc["public_keys"]) == 2
        kids = [k["kid"] for k in doc["public_keys"]]
        assert old_kid in kids
        assert plan["new_kid"] in kids

        # Complete rotation: old key removed, added to revocation
        rev_doc = build_revocation_document("example.com")
        complete_rotation(doc, rev_doc, old_kid, "superseded")

        assert len(doc["public_keys"]) == 1
        assert doc["public_keys"][0]["kid"] == plan["new_kid"]
        assert len(rev_doc["revoked_keys"]) == 1
        assert rev_doc["revoked_keys"][0]["kid"] == old_kid
        assert rev_doc["revoked_keys"][0]["reason"] == "superseded"


class TestPinningFlow:
    def test_tofu_pinning(self):
        _priv1, pub1 = generate_key_pair()
        kid1 = generate_key_id(pub1)
        jwk1 = pem_to_jwk(pub1, kid1)

        store = KeyPinStore()

        # First verification pins the key
        result1 = check_pinning(store, "example.com", jwk1)
        assert result1 == PinningResult.FIRST_USE

        # Same key succeeds
        result2 = check_pinning(store, "example.com", jwk1)
        assert result2 == PinningResult.MATCHED

        # Different key triggers error
        _priv2, pub2 = generate_key_pair()
        kid2 = generate_key_id(pub2)
        jwk2 = pem_to_jwk(pub2, kid2)

        with pytest.raises(AgentPinError):
            check_pinning(store, "example.com", jwk2)
