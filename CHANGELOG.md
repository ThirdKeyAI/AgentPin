# Changelog

All notable changes to the AgentPin project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0-alpha.1] - 2026-05-01

### Added

#### A2A AgentCard Extension Types & Resolvers (Rust)

- **`AllowedDomains` type** in `types::discovery` — typed wrapper over the list of domains an agent is permitted to interact with. Extracted from `Constraints::allowed_domains` via the new `Constraints::allowed_domains_typed()` helper. Empty list = no restriction (all domains trusted) per the established cross-protocol convention. Includes `intersect()` for composing with cross-protocol callers (most importantly SchemaPin v1.4's `A2aVerificationContext`, which scopes tool verification to the intersection of caller and provider domains).
- **`A2aAgentCard` + supporting types** in `types::a2a` — minimal A2A AgentCard subset (`A2aAgentCard`, `A2aAgentCapabilities`, `A2aAgentSkill`) plus the AgentPin-specific `AgentpinExtension` payload (`agentpin_endpoint`, `public_key_jwk`, `signature`). Inline definition rather than depending on the upstream `a2a-types` crate while the A2A spec is still draft — the public surface lets us re-export from upstream once it stabilises without breaking callers.
- **`A2aAgentCardBuilder`** in new `a2a` module — turns an `AgentDeclaration` into a signed `A2aAgentCard`. Maps capabilities to skills via `capability_to_skill`, propagates `Constraints::allowed_domains` into `A2aAgentCapabilities::allowed_domains`. Detached ECDSA P-256 signature covers the canonical bytes of the AgentCard with the extension cleared.
- **`verify_agentpin_extension(card)`** — verifies the AgentPin extension signature against the JWK embedded in the extension. Sorted-key canonical JSON; matches the canonicalisation pattern used by SchemaPin.
- **`LocalAgentCardStore`** in new `resolver_local` module — in-memory store of pre-registered AgentCards keyed by their AgentPin discovery domain. Implements `DiscoveryResolver` (always available, no `fetch` feature). Verifies the AgentPin extension signature at registration time and pre-derives a `DiscoveryDocument` so the rest of the AgentPin verification stack runs unchanged. Supports Symbiont v1.7.0's push-based external-agent registration where the coordinator receives AgentCard JSON inline rather than fetching it from a `.well-known` endpoint.
- **`A2aAgentCardResolver`** in new `resolver_a2a` module (gated on `fetch`) — fetches `https://{domain}/.well-known/agent-card.json`, verifies the AgentPin extension, cross-checks that the embedded `agentpin_endpoint` host matches the fetched domain, and derives a `DiscoveryDocument`. `last_card()` exposes the original A2A representation alongside the derived doc for callers that want both.
- **`a2a_endpoint` field** on `DiscoveryDocument` — optional URL of the entity's A2A AgentCard endpoint, enabling cross-protocol discovery.

### Notes

- This is the first v0.3.0 alpha — the unblock for **Symbiont v1.8.0 Phase 3** (AgentPin-verified AgentCards, A2A auth middleware) and **SchemaPin v1.4.0 `A2aVerificationContext`** (which consumes `AllowedDomains` for tool-verification scoping). Both downstream releases were waiting on this surface.
- All additions are purely additive — v0.2.0 callers are unaffected. Discovery documents without `a2a_endpoint` and AgentCards without an `agentpin` extension behave exactly as before.
- JavaScript and Python SDK ports follow in `0.3.0-alpha.2`. The Go SDK (separate priority) follows in its own release.

## [0.2.0] - 2026-02-12

### Added

#### Trust Bundles & Alternative Discovery
- **Trust bundles** for offline and air-gapped verification — pre-package discovery + revocation data
- **`DiscoveryResolver` trait** with pluggable discovery strategies:
  - `WellKnownResolver`: HTTP `.well-known` lookups (default)
  - `DnsTxtResolver`: DNS TXT record discovery
  - `ManualResolver`: Pre-configured static documents
- **`directory_listing` field** on `AgentDeclaration` for multi-agent domain enumeration
- **JavaScript SDK**: Trust bundle support, resolver abstraction
- **Python SDK**: Trust bundle support, resolver abstraction

## [0.1.1] - 2026-02-10

### Fixed
- **PyPI README**: Added package README for PyPI listing
- **npm README**: Added package README, fixed package URLs
- Bumped JavaScript package to 0.1.1, Python package to 0.1.1

## [0.1.0] - 2026-02-08

### Added

#### Core Protocol
- **ECDSA P-256 keypair generation** with JWK export
- **JWT credential issuance** (ES256 signed, configurable TTL)
- **12-step credential verification** flow:
  - JWT parsing, algorithm validation (ES256 only), signature verification
  - Domain binding, discovery resolution, key matching
  - TOFU key pinning (JWK thumbprint), expiration, revocation
  - Capability validation, delegation chain verification
- **TOFU key pinning** with JWK thumbprint persistence
- **Delegation chains** with capability narrowing and depth limits
- **Mutual authentication** with 128-bit nonce challenge-response
- **Credential, agent, and key-level revocation**

#### Crates
- `agentpin` — Core library (no mandatory HTTP dependency)
- `agentpin-cli` — CLI binary (`keygen`, `issue`, `verify`, `bundle`)
- `agentpin-server` — Axum server for `.well-known` endpoints

#### Cross-Language SDKs
- **JavaScript** (`agentpin` npm package): Full protocol implementation
- **Python** (`agentpin` PyPI package): Full protocol implementation

#### Discovery
- `.well-known/agent-identity.json` discovery document format
- `.well-known/agent-identity-revocations.json` revocation endpoint
- Capability-scoped credentials with constraints (`max_ttl_secs`, `allowed_scopes`)
