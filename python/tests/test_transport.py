"""Tests for transport binding helpers."""

import json

import pytest

from agentpin.transport import (
    AUTH_TYPE,
    FIELD_NAME,
    GRPC_METADATA_KEY,
    grpc_extract_credential,
    grpc_format_metadata_value,
    http_extract_credential,
    http_format_authorization_header,
    mcp_extract_credential,
    mcp_format_meta_field,
    ws_extract_credential,
    ws_format_auth_message,
)
from agentpin.types import AgentPinError


class TestHttpTransport:
    def test_extract_valid(self):
        assert http_extract_credential("AgentPin eyJ.test.jwt") == "eyJ.test.jwt"

    def test_extract_missing_prefix(self):
        with pytest.raises(AgentPinError, match="Missing 'AgentPin ' prefix"):
            http_extract_credential("Bearer eyJ.test.jwt")

    def test_extract_empty_credential(self):
        with pytest.raises(AgentPinError, match="Empty credential"):
            http_extract_credential("AgentPin ")

    def test_format_roundtrip(self):
        jwt = "eyJ.test.jwt"
        header = http_format_authorization_header(jwt)
        assert header == "AgentPin eyJ.test.jwt"
        assert http_extract_credential(header) == jwt


class TestMcpTransport:
    def test_extract_valid(self):
        meta = {FIELD_NAME: "eyJ.test.jwt"}
        assert mcp_extract_credential(meta) == "eyJ.test.jwt"

    def test_extract_missing_field(self):
        with pytest.raises(AgentPinError, match="Missing"):
            mcp_extract_credential({})

    def test_extract_non_string(self):
        with pytest.raises(AgentPinError, match="not a string"):
            mcp_extract_credential({FIELD_NAME: 42})

    def test_format_roundtrip(self):
        jwt = "eyJ.test.jwt"
        meta = mcp_format_meta_field(jwt)
        assert mcp_extract_credential(meta) == jwt


class TestWsTransport:
    def test_extract_valid(self):
        msg = json.dumps({"type": AUTH_TYPE, "credential": "eyJ.test.jwt"})
        assert ws_extract_credential(msg) == "eyJ.test.jwt"

    def test_extract_invalid_json(self):
        with pytest.raises(AgentPinError, match="Invalid JSON"):
            ws_extract_credential("not json")

    def test_extract_wrong_type(self):
        msg = json.dumps({"type": "other", "credential": "eyJ.test.jwt"})
        with pytest.raises(AgentPinError, match="Expected type"):
            ws_extract_credential(msg)

    def test_extract_missing_credential(self):
        msg = json.dumps({"type": AUTH_TYPE})
        with pytest.raises(AgentPinError, match="Missing or non-string"):
            ws_extract_credential(msg)

    def test_format_roundtrip(self):
        jwt = "eyJ.test.jwt"
        msg = ws_format_auth_message(jwt)
        assert ws_extract_credential(msg) == jwt


class TestGrpcTransport:
    def test_extract_valid(self):
        assert grpc_extract_credential("eyJ.test.jwt") == "eyJ.test.jwt"

    def test_extract_empty(self):
        with pytest.raises(AgentPinError, match="Empty gRPC metadata"):
            grpc_extract_credential("")

    def test_format_roundtrip(self):
        jwt = "eyJ.test.jwt"
        value = grpc_format_metadata_value(jwt)
        assert grpc_extract_credential(value) == jwt

    def test_metadata_key_name(self):
        assert GRPC_METADATA_KEY == "agentpin-credential"
