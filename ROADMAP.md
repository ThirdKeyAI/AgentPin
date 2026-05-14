# AgentPin Roadmap

![Version](https://img.shields.io/badge/current-v0.3.0-brightgreen)
![Next](https://img.shields.io/badge/next-v0.4.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**Domain-anchored cryptographic identity for AI agents — the identity layer of the ThirdKey trust stack.**

---

## Release Timeline

| Version | Target | Headline | Status |
|---------|--------|----------|--------|
| **v0.1.0** | 2026-01 | Core identity, verification, delegation | Shipped |
| **v0.2.0** | 2026-02 | Trust bundles, alternative discovery, directory listing | Shipped |
| **v0.3.0** | 2026-05-14 | A2A AgentCard extension types + resolvers + AllowedDomains + DNS TXT (Rust, JavaScript, Python, Go) | **Shipped** |
| **v0.4.0** | Q3 2026 | Mutual auth as A2A handshake, hardware-backed keys | Planning |
| **v1.0.0** | Q4 2026 | Stable API, full specification compliance | Planning |

---

## v0.2.0 — Shipped

Trust bundles for offline verification, `DiscoveryResolver` trait for pluggable discovery mechanisms (well-known, DNS TXT, manual), `directory_listing` field on `AgentDeclaration` for multi-agent domains, and cross-language support in JavaScript and Python SDKs.

See [CHANGELOG.md](CHANGELOG.md) for full release notes.

---

## v0.3.0 — Shipped (2026-05-14)

AgentPin became the cryptographic identity layer for A2A (Agent-to-Agent)
networks. Four-language parity (Rust, JavaScript, Python, Go) for the A2A
AgentCard extension surface and DNS TXT cross-verification: cards signed in
any of the four SDKs verify cleanly in the other three.

Highlights:

- **A2A AgentCard extension** — signed AgentCards published at
  `/.well-known/agent-card.json` with an AgentPin payload
  (`agentpin_endpoint`, `public_key_jwk`, `signature`). Detached ECDSA P-256
  signature over the canonical bytes of the card with the extension
  cleared, byte-identical across all four SDKs.
- **Resolvers** — `A2aAgentCardResolver` for HTTPS fetch + extension
  verification + endpoint-host cross-check; `LocalAgentCardStore` for
  in-memory pre-registered cards (backs Symbiont's push-based external-
  agent registration).
- **`AllowedDomains` typed wrapper** — empty list = unrestricted convention
  shared with SchemaPin v1.4 `A2aVerificationContext` for intersection-
  based tool-verification scoping.
- **DNS TXT cross-verification** — `_agentpin.{domain}` IN TXT
  `"v=agentpin1; kid=...; fp=sha256:<hex>"`. Fail-closed on mismatch
  because an intentional publish signals DNS is part of the trust chain.
- **Go SDK** — initial fourth-language port at the v0.3.0 surface,
  including A2A and DNS modules. Module path
  `github.com/ThirdKeyAi/agentpin/go`, mirrors the SchemaPin Go SDK layout.

See [CHANGELOG.md](CHANGELOG.md#030---2026-05-14) for full release notes.

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

### Hardware-Backed Keys

| Item | Details |
|------|---------|
| HSM support | Sign credentials and AgentCards via PKCS#11-compatible HSMs |
| TPM support | TPM 2.0 backend for OS-bound signing keys |
| Key migration | Helpers to migrate existing software keys onto hardware-backed slots |

---

## v1.0.0 — Stable API (Q4 2026)

| Item | Details |
|------|---------|
| API audit | Review and stabilize all public types — remove experimental markers |
| A2A types | Finalize `A2aAgentCard`, `AgentpinExtension`, and related types; re-export upstream `a2a-types` once that crate stabilises |
| Integration tests | Comprehensive test suite covering AgentPin + A2A interop scenarios |
| Specification | Published spec for AgentPin identity model and A2A extension format |
| Cross-language | Full parity across Rust, JavaScript, Python, and Go — identical verification guarantees |

---

## Beyond (Unscheduled)

| Feature | Description |
|---------|-------------|
| Delegated A2A Auth | Delegate identity verification to trusted intermediaries for hub-and-spoke topologies |
| Agent Directory Protocol | Standardized directory for discovering agents by capability, domain, or trust level |
| Key Rotation for A2A | Seamless key rotation with grace periods — A2A peers notified via protocol extension |

---

## Contributing

We welcome input on roadmap priorities:

- **GitHub Discussions** — Open a discussion in the [AgentPin repository](https://github.com/ThirdKeyAI/agentpin/discussions)
- **Contributing Guide** — See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup
- **Security** — For security-sensitive feedback, see SECURITY.md

---

*Last updated: 2026-05-14 (v0.3.0 shipped — A2A AgentCard types, AllowedDomains, LocalAgentCardStore, A2aAgentCardResolver, DNS TXT cross-verification across Rust, JavaScript, Python, and Go)*
