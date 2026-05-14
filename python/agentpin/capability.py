"""Capability parsing, matching, and validation for AgentPin."""

import json
from typing import List, Optional, Tuple

from .crypto import sha256_hex


class Capability:
    """A capability in `action:resource` format."""

    def __init__(self, value: str):
        self.value = value

    @staticmethod
    def create(action: str, resource: str) -> "Capability":
        return Capability(f"{action}:{resource}")

    @staticmethod
    def parse(s: str) -> Optional[Tuple[str, str]]:
        idx = s.find(":")
        if idx == -1:
            return None
        return s[:idx], s[idx + 1 :]

    @property
    def action(self) -> Optional[str]:
        parsed = Capability.parse(self.value)
        return parsed[0] if parsed else None

    @property
    def resource(self) -> Optional[str]:
        parsed = Capability.parse(self.value)
        return parsed[1] if parsed else None

    def matches(self, requested: "Capability") -> bool:
        """Check if this capability matches a requested capability.

        Wildcard resources (`*`) match any resource with the same action.
        Scoped resources match if the requested resource starts with the declared resource + '.'.
        """
        self_parsed = Capability.parse(self.value)
        req_parsed = Capability.parse(requested.value)
        if not self_parsed or not req_parsed:
            return False

        self_action, self_resource = self_parsed
        req_action, req_resource = req_parsed

        if self_action != req_action:
            return False
        if self_resource == "*":
            return True
        if self_resource == req_resource:
            return True

        # Scoped matching
        if (
            req_resource.startswith(self_resource)
            and len(req_resource) > len(self_resource)
            and req_resource[len(self_resource)] == "."
        ):
            return True

        return False

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"Capability({self.value!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Capability):
            return self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


def capabilities_subset(declared: List[Capability], requested: List[Capability]) -> bool:
    """Check that all requested capabilities are covered by declared capabilities."""
    return all(any(decl.matches(req) for decl in declared) for req in requested)


def capabilities_hash(capabilities: List[Capability]) -> str:
    """Hash capabilities for delegation attestation: SHA-256 of sorted JSON array."""
    sorted_caps = sorted(c.value for c in capabilities)
    json_str = json.dumps(sorted_caps, separators=(",", ":"))
    return sha256_hex(json_str.encode("utf-8"))


CORE_ACTIONS = ["read", "write", "execute", "admin", "delegate"]


def _is_reverse_domain(s: str) -> bool:
    """Check if string looks like a reverse domain prefix (contains a dot)."""
    return "." in s


def validate_capability(cap: Capability) -> None:
    """Validate a capability against the AgentPin taxonomy.

    Raises ValueError if invalid.
    Rules:
    - Must be action:resource format
    - admin:* wildcard rejected
    - Custom (non-core) actions must use reverse-domain prefix
    """
    parsed = Capability.parse(cap.value)
    if not parsed:
        raise ValueError(
            f"Invalid capability format (missing ':'): {cap.value}"
        )
    action, resource = parsed
    if action == "admin" and resource == "*":
        raise ValueError(
            "admin:* wildcard is not allowed; admin capabilities must be explicitly scoped"
        )
    if action in CORE_ACTIONS:
        return
    if not _is_reverse_domain(action):
        raise ValueError(
            f"Custom action '{action}' must use reverse-domain prefix "
            f"(e.g., com.example.{action})"
        )
