# AgentPin

Domain-anchored cryptographic identity for AI agents. The second layer in the [ThirdKey](https://thirdkey.ai) trust stack (SchemaPin → **AgentPin** → Symbiont).

**[Read the Documentation →](https://docs.agentpin.org)**

## What It Does

AgentPin lets organizations publish verifiable identity for their AI agents. Issue short-lived ES256 credentials, verify agent identity with a 12-step protocol, and enforce capability-scoped access — all anchored to your domain via `.well-known` discovery.

- **ES256 (ECDSA P-256)** cryptographic credentials
- **Domain-anchored** `.well-known/agent-identity.json` discovery
- **12-step verification** with TOFU key pinning
- **Delegation chains** for maker-deployer models
- **Capability-scoped credentials** with constraints
- **Credential revocation** at credential, agent, and key level
- **Mutual authentication** with challenge-response
- **Trust bundles** for air-gapped and enterprise environments
- **Cross-language** — Rust, JavaScript, and Python SDKs produce interoperable credentials

## Quick Start

```bash
# Generate keys
agentpin keygen --domain example.com --kid my-key-2026 --output-dir ./keys

# Issue a credential
agentpin issue \
  --private-key ./keys/my-key-2026.private.pem \
  --kid my-key-2026 --issuer example.com \
  --agent-id "urn:agentpin:example.com:scout" \
  --capabilities "read:data,write:reports" --ttl 3600

# Verify a credential
agentpin verify --credential <jwt>
```

**[Getting Started Guide →](https://docs.agentpin.org/getting-started/)**

## Installation

### Rust

```toml
[dependencies]
agentpin = { version = "0.1", features = ["fetch"] }
```

### JavaScript

```bash
npm install agentpin
```

### Python

```bash
pip install agentpin
```

## Documentation

| Topic | Link |
|-------|------|
| Getting Started | [docs.agentpin.org/getting-started](https://docs.agentpin.org/getting-started/) |
| Verification Flow | [docs.agentpin.org/verification-flow](https://docs.agentpin.org/verification-flow/) |
| CLI Reference | [docs.agentpin.org/cli-guide](https://docs.agentpin.org/cli-guide/) |
| Trust Bundles | [docs.agentpin.org/trust-bundles](https://docs.agentpin.org/trust-bundles/) |
| Delegation Chains | [docs.agentpin.org/delegation-chains](https://docs.agentpin.org/delegation-chains/) |
| Deployment | [docs.agentpin.org/deployment](https://docs.agentpin.org/deployment/) |
| Security | [docs.agentpin.org/security](https://docs.agentpin.org/security/) |
| Technical Specification | [AGENTPIN_TECHNICAL_SPECIFICATION.md](AGENTPIN_TECHNICAL_SPECIFICATION.md) |

## Project Structure

```
crates/
├── agentpin/          # Core Rust library
├── agentpin-cli/      # CLI binary
└── agentpin-server/   # HTTP server for .well-known endpoints
javascript/            # JavaScript/Node.js SDK
python/                # Python SDK
```

## License

MIT — Jascha Wanger / [ThirdKey.ai](https://thirdkey.ai)
