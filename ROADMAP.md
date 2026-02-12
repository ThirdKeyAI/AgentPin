# AgentPin Roadmap

![Version](https://img.shields.io/badge/current-v0.2.0-brightgreen)
![Next](https://img.shields.io/badge/next-v0.3.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Domain-anchored cryptographic identity for AI agents — the identity layer of the ThirdKey trust stack.**

---

## Release Timeline

| Version | Target | Headline | Status |
|---------|--------|----------|--------|
| **v0.1.0** | 2026-01 | Core identity, verification, delegation | Shipped |
| **v0.2.0** | 2026-02 | Trust bundles, alternative discovery, directory listing | Shipped |
| **v0.3.0** | Q2 2026 | A2A AgentCard extension types + resolver | Planning |
| **v0.4.0** | Q3 2026 | Mutual auth as A2A handshake, cross-language parity | Planning |
| **v1.0.0** | Q4 2026 | Stable API, full specification compliance | Planning |

---

## v0.2.0 — Shipped

Trust bundles for offline verification, `DiscoveryResolver` trait for pluggable discovery mechanisms (well-known, DNS TXT, manual), `directory_listing` field on `AgentDeclaration` for multi-agent domains, and cross-language support in JavaScript and Python SDKs.

See [CHANGELOG.md](CHANGELOG.md) for full release notes.

---

## v0.3.0 — A2A AgentCard Types + Resolver (Q2 2026)

AgentPin becomes the cryptographic identity layer for A2A (Agent-to-Agent) networks. This release defines extension types for A2A AgentCards and a resolver that discovers AgentPin identity from A2A endpoints.

### A2A AgentCard Extension Types

| Item | Details |
|------|---------|
| `A2aAgentCardExtension` | New type: `agentpin_endpoint`, `public_key_jwk`, `signature` fields |
| `A2aAgentCardBuilder` | Constructs signed A2A AgentCard from `AgentDeclaration` + signing key |
| Capability mapping | `AgentDeclaration.capabilities` → `AgentSkill`, `AgentDeclaration.constraints` → `AgentCapabilities` |
| Verification | Validate A2A extensions during 12-step verification |

### A2A AgentCard Resolver

| Item | Details |
|------|---------|
| `A2aAgentCardResolver` | Implements `DiscoveryResolver` — fetches `/.well-known/agent-card.json`, extracts AgentPin extensions |
| Fallback chain | Try A2A card first, fall back to `agent-identity.json` via `WellKnownResolver` |
| Feature flag | Optional dependency on `a2a-types` behind `a2a` feature flag |

### Touchpoints

| Area | Change |
|------|--------|
| New | `src/types/a2a.rs` — `A2aAgentCardExtension`, `A2aAgentCardBuilder` |
| New | `src/a2a.rs` — A2A extension signing and validation logic |
| New | `src/resolver_a2a.rs` — `A2aAgentCardResolver` implementing `DiscoveryResolver` |
| Extend | `src/types/discovery.rs` — `a2a_endpoint` field on discovery types |

---

## v0.4.0 — Mutual Auth as A2A Handshake (Q3 2026)

Adapts AgentPin's challenge-response mutual authentication as an A2A handshake protocol, enabling agents to cryptographically verify each other's identity before exchanging tasks.

### Mutual Authentication

| Item | Details |
|------|---------|
| JSON-RPC methods | `agentpin/challenge` and `agentpin/response` — challenge-response over A2A transport |
| Session binding | After successful mutual auth, bind verified identity to A2A session |
| `MutualAuthPolicy` | `Required` \| `Optional` \| `Disabled` — configurable per agent |
| Nonce expiry | Configurable nonce TTL for A2A use cases (shorter default than general use) |

### Cross-Language Parity

JavaScript and Python SDKs gain matching implementations:

- `A2aAgentCardExtension`, `A2aAgentCardBuilder`, `A2aAgentCardResolver`
- Mutual auth JSON-RPC helpers (`createChallenge`, `verifyResponse`)
- Feature-flag equivalents for A2A dependencies

---

## v1.0.0 — Stable API (Q4 2026)

| Item | Details |
|------|---------|
| API audit | Review and stabilize all public types — remove experimental markers |
| A2A types | Finalize `A2aAgentCardExtension` and related types |
| Integration tests | Comprehensive test suite covering AgentPin + A2A interop scenarios |
| Specification | Published spec for AgentPin identity model and A2A extension format |
| Cross-language | Full parity across Rust, JavaScript, and Python — identical verification guarantees |

---

## Beyond (Unscheduled)

| Feature | Description |
|---------|-------------|
| Delegated A2A Auth | Delegate identity verification to trusted intermediaries for hub-and-spoke topologies |
| Agent Directory Protocol | Standardized directory for discovering agents by capability, domain, or trust level |
| Key Rotation for A2A | Seamless key rotation with grace periods — A2A peers notified via protocol extension |
| Hardware-Backed Keys | HSM and TPM support for agent signing keys |

---

## Contributing

We welcome input on roadmap priorities:

- **GitHub Discussions** — Open a discussion in the [AgentPin repository](https://github.com/ThirdKeyAI/agentpin/discussions)
- **Contributing Guide** — See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup
- **Security** — For security-sensitive feedback, see SECURITY.md

---

*Last updated: 2026-02-12*
