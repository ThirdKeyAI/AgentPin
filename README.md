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
- **Signed A2A AgentCards** (v0.3) — extends the [A2A](https://github.com/google-a2a/A2A) AgentCard format with an AgentPin cryptographic-identity payload. `LocalAgentCardStore` for push-registered agents, `A2aAgentCardResolver` for `.well-known/agent-card.json` fetches.
- **DNS TXT cross-verification** (v0.3) — second-channel trust via `_agentpin.{domain}` TXT records (`v=agentpin1; kid=...; fp=sha256:<hex>`), defending against HTTPS-origin and TLS cert mis-issuance compromise.
- **`AllowedDomains` typed wrapper** (v0.3) — empty-list-equals-unrestricted convention with intersection semantics for cross-protocol scoping with SchemaPin v1.4 `A2aVerificationContext`.
- **Cross-language** — Rust, JavaScript, Python, and Go SDKs produce interoperable credentials and AgentCards. Cards signed in any SDK verify cleanly in the other three.

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
agentpin = { version = "0.3", features = ["fetch"] }
```

### JavaScript

```bash
npm install agentpin
```

### Python

```bash
pip install agentpin
```

### Go

```bash
go install github.com/ThirdKeyAi/agentpin/go/cmd/agentpin@latest
go get github.com/ThirdKeyAi/agentpin/go
```

## Documentation

| Topic | Link |
|-------|------|
| Getting Started | [docs.agentpin.org/getting-started](https://docs.agentpin.org/getting-started/) |
| Verification Flow | [docs.agentpin.org/verification-flow](https://docs.agentpin.org/verification-flow/) |
| A2A AgentCards (v0.3) | [docs/a2a-agentcards.md](docs/a2a-agentcards.md) |
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
go/                    # Go SDK
```

## License

MIT — Jascha Wanger / [ThirdKey.ai](https://thirdkey.ai)
