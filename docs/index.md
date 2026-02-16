# AgentPin

**Domain-anchored cryptographic identity for AI agents.**

AgentPin is the identity layer of the [ThirdKey](https://thirdkey.ai) trust stack: [SchemaPin](https://schemapin.org) (tool integrity) → **AgentPin** (agent identity) → [Symbiont](https://symbiont.dev) (runtime).

---

## What AgentPin Does

AgentPin lets organizations publish verifiable identity for their AI agents and verify agent identity using a 12-step cryptographic protocol:

- **Discovery** — Publish `/.well-known/agent-identity.json` declaring agents, keys, and capabilities
- **Credentials** — ES256 (ECDSA P-256) signed JWTs with agent identity and scoped capabilities
- **Verification** — 12-step protocol: parsing, algorithm check, temporal validation, discovery, signature, domain binding, key matching, agent status, revocation, capability validation, delegation chains, TOFU key pinning
- **Delegation** — Maker-deployer chains with capability narrowing
- **Mutual Auth** — Challenge-response with 128-bit nonces
- **Revocation** — Credential, agent, and key-level revocation

## Quick Example

```python
from agentpin import (
    generate_key_pair, generate_key_id, pem_to_jwk,
    issue_credential, verify_credential_offline,
    build_discovery_document, KeyPinStore, Capability,
)

# Generate keys
private_key, public_key = generate_key_pair()
kid = generate_key_id(public_key)
jwk = pem_to_jwk(public_key, kid)

# Build discovery document
discovery = build_discovery_document(
    "example.com", "maker", [jwk],
    [{"agent_id": "urn:agentpin:example.com:agent", "name": "My Agent",
      "capabilities": ["read:data"], "status": "active"}], 2,
)

# Issue credential
credential = issue_credential(
    private_key, kid, "example.com", "urn:agentpin:example.com:agent",
    "verifier.com", [Capability.create("read", "data")], None, None, 3600,
)

# Verify
result = verify_credential_offline(credential, discovery, None, KeyPinStore(), "verifier.com")
print(f"Valid: {result.valid}, Agent: {result.agent_id}")
```

## Implementations

| Language | Package | Install |
|----------|---------|---------|
| **Rust** | `agentpin` | `cargo add agentpin` |
| **JavaScript** | `agentpin` | `npm install agentpin` |
| **Python** | `agentpin` | `pip install agentpin` |

All implementations produce interoperable credentials — a JWT issued by one language can be verified by any other.

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](getting-started.md) | Install, generate keys, issue and verify credentials |
| [Verification Flow](verification-flow.md) | The 12-step verification protocol explained |
| [CLI Guide](cli-guide.md) | `agentpin keygen`, `issue`, `verify`, and server commands |
| [Trust Bundles](trust-bundles.md) | Offline and air-gapped verification |
| [Delegation Chains](delegation-chains.md) | Maker-deployer trust model |
| [Deployment](deployment.md) | Serve `.well-known` endpoints in production |
| [Security](security.md) | Threat model and best practices |
| [Troubleshooting](troubleshooting.md) | Common errors and solutions |

## Links

- [GitHub](https://github.com/ThirdKeyAI/agentpin)
- [Website](https://agentpin.org)
- [Technical Specification](https://github.com/ThirdKeyAI/agentpin/blob/main/AGENTPIN_TECHNICAL_SPECIFICATION.md)
- [Roadmap](https://github.com/ThirdKeyAI/agentpin/blob/main/ROADMAP.md)
