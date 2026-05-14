"""Transport binding helpers for AgentPin (spec Section 13)."""

import json

from .types import AgentPinError, ErrorCode

# --- HTTP ---


def http_extract_credential(header_value: str) -> str:
    """Extract JWT from 'Authorization: AgentPin <JWT>' header value."""
    prefix = "AgentPin "
    if not header_value.startswith(prefix):
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            "Missing 'AgentPin ' prefix in Authorization header",
        )
    jwt = header_value[len(prefix):]
    if not jwt:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            "Empty credential in Authorization header",
        )
    return jwt


def http_format_authorization_header(jwt: str) -> str:
    """Format JWT for Authorization header: 'AgentPin <jwt>'."""
    return f"AgentPin {jwt}"


# --- MCP ---

FIELD_NAME = "agentpin_credential"


def mcp_extract_credential(meta: dict) -> str:
    """Extract JWT from MCP metadata dict's 'agentpin_credential' field."""
    if FIELD_NAME not in meta:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            f"Missing '{FIELD_NAME}' field in MCP metadata",
        )
    value = meta[FIELD_NAME]
    if not isinstance(value, str):
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            f"'{FIELD_NAME}' field is not a string",
        )
    return value


def mcp_format_meta_field(jwt: str) -> dict:
    """Format JWT as MCP metadata dict."""
    return {FIELD_NAME: jwt}


# --- WebSocket ---

AUTH_TYPE = "agentpin-auth"


def ws_extract_credential(message: str) -> str:
    """Extract JWT from WebSocket JSON auth message."""
    try:
        parsed = json.loads(message)
    except json.JSONDecodeError as e:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED, f"Invalid JSON: {e}"
        )
    msg_type = parsed.get("type")
    if msg_type != AUTH_TYPE:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            f"Expected type '{AUTH_TYPE}', got '{msg_type}'",
        )
    credential = parsed.get("credential")
    if not isinstance(credential, str):
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED,
            "Missing or non-string 'credential' field",
        )
    return credential


def ws_format_auth_message(jwt: str) -> str:
    """Format JWT as WebSocket auth message JSON string."""
    return json.dumps({"type": AUTH_TYPE, "credential": jwt})


# --- gRPC ---

GRPC_METADATA_KEY = "agentpin-credential"


def grpc_extract_credential(metadata_value: str) -> str:
    """Extract JWT from gRPC metadata value."""
    if not metadata_value:
        raise AgentPinError(
            ErrorCode.DISCOVERY_FETCH_FAILED, "Empty gRPC metadata value"
        )
    return metadata_value


def grpc_format_metadata_value(jwt: str) -> str:
    """Format JWT for gRPC metadata (identity function, documents key name)."""
    return jwt
