"""Tests for key rotation helpers."""

from agentpin.crypto import generate_key_id, generate_key_pair
from agentpin.jwk import pem_to_jwk
from agentpin.revocation import build_revocation_document
from agentpin.rotation import apply_rotation, complete_rotation, prepare_rotation


class TestRotation:
    def test_prepare_rotation(self):
        _, pub = generate_key_pair()
        old_kid = generate_key_id(pub)
        plan = prepare_rotation(old_kid)

        assert plan["old_kid"] == old_kid
        assert plan["new_kid"] != old_kid
        assert plan["new_jwk"]["kid"] == plan["new_kid"]
        assert len(plan["new_key_pair"]) == 2  # (private, public)

    def test_apply_rotation(self):
        # Build a minimal discovery doc
        _, pub = generate_key_pair()
        old_kid = generate_key_id(pub)
        old_jwk = pem_to_jwk(pub, old_kid)
        doc = {"public_keys": [old_jwk], "updated_at": "old"}

        plan = prepare_rotation(old_kid)
        apply_rotation(doc, plan)

        assert len(doc["public_keys"]) == 2
        kids = [k["kid"] for k in doc["public_keys"]]
        assert old_kid in kids
        assert plan["new_kid"] in kids
        assert doc["updated_at"] != "old"

    def test_complete_rotation(self):
        # Build docs
        _, pub = generate_key_pair()
        old_kid = generate_key_id(pub)
        old_jwk = pem_to_jwk(pub, old_kid)

        plan = prepare_rotation(old_kid)
        doc = {"public_keys": [old_jwk, plan["new_jwk"]], "updated_at": "old"}
        rev_doc = build_revocation_document("example.com")

        complete_rotation(doc, rev_doc, old_kid, "key_compromise")

        # Old key removed from discovery
        kids = [k["kid"] for k in doc["public_keys"]]
        assert old_kid not in kids
        assert plan["new_kid"] in kids
        assert len(doc["public_keys"]) == 1

        # Old key added to revocation
        assert len(rev_doc["revoked_keys"]) == 1
        assert rev_doc["revoked_keys"][0]["kid"] == old_kid
        assert rev_doc["revoked_keys"][0]["reason"] == "key_compromise"
