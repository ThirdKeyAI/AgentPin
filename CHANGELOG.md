# Changelog

All notable changes to the AgentPin project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-05-14

### Added

Four-language parity (Rust, JavaScript, Python, Go) for the A2A AgentCard
extension surface and DNS TXT cross-verification. Cards signed in any of the
four SDKs verify cleanly in the other three; signature canonicalisation is
byte-identical across implementations.

#### A2A AgentCard extension types, signed builder, and verifier

- **`A2aAgentCard` + supporting types** — minimal A2A AgentCard subset
  (`A2aAgentCard`, `A2aAgentCapabilities`, `A2aAgentSkill`) plus the
  AgentPin-specific `AgentpinExtension` payload (`agentpin_endpoint`,
  `public_key_jwk`, `signature`). Inline definition rather than depending on
  the upstream `a2a-types` crate while the A2A spec is still draft.
- **`A2aAgentCardBuilder`** (Rust) / `buildAndSignAgentCard` (JS) /
  `build_and_sign_agent_card` (Python) / `a2a.BuildAndSignAgentCard` (Go) —
  turns an AgentDeclaration into a signed `A2aAgentCard`. Maps capabilities
  to skills via `capability_to_skill`; propagates `allowed_domains` from the
  source constraints into `A2aAgentCapabilities.allowed_domains`. Detached
  ECDSA P-256 signature covers the canonical bytes of the AgentCard with the
  extension cleared.
- **`verify_agentpin_extension(card)`** — verifies the AgentPin extension
  signature against the JWK embedded in the extension. Sorted-key canonical
  JSON shared across all four SDKs; mirrors the canonicalisation pattern
  used by SchemaPin.
- **`AllowedDomains` typed wrapper** — extracted from
  `Constraints::allowed_domains` and exposed for cross-protocol use
  (SchemaPin v1.4's `A2aVerificationContext` scopes tool verification to the
  intersection of caller and provider domains). Empty list = no restriction
  (all domains trusted) by convention; `intersect(unrestricted, X) = X`.
- **`a2a_endpoint` field** on `DiscoveryDocument` — optional URL of the
  entity's A2A AgentCard endpoint, enabling cross-protocol discovery.

#### Discovery resolvers for A2A AgentCards

- **`LocalAgentCardStore`** (all SDKs) — in-memory store of pre-registered
  AgentCards keyed by their AgentPin discovery domain. Verifies the
  AgentPin extension signature at registration time and pre-derives a
  `DiscoveryDocument` so the rest of the AgentPin verification stack runs
  unchanged. Supports Symbiont's push-based external-agent registration
  flow where the coordinator receives AgentCard JSON inline rather than
  fetching it from a `.well-known` endpoint.
- **`A2aAgentCardResolver`** (all SDKs; gated on `fetch` in Rust) — fetches
  `https://{domain}/.well-known/agent-card.json`, verifies the AgentPin
  extension, cross-checks that the embedded `agentpin_endpoint` host
  matches the fetched domain, and derives a `DiscoveryDocument`. Exposes
  the original A2A representation alongside the derived doc for callers
  that want both.

#### DNS TXT cross-verification at `_agentpin.{domain}`

- **`dns` module** (all SDKs) — `parse_txt_record`, `verify_dns_match`,
  `txt_record_name`. Wire format mirrors SchemaPin's `_schemapin.{domain}`
  record with the version tag changed:
  `"v=agentpin1; kid=...; fp=sha256:<hex>"`. Whitespace-tolerant parser,
  case-insensitive on `fp`, ignores unknown fields for forward
  compatibility.
- **`fetch_dns_txt(domain)`** — Rust: async lookup behind the new `dns`
  Cargo feature (`hickory-resolver`, `tokio`, `async-trait`). JavaScript:
  uses Node's built-in `dns/promises`. Python: uses the optional
  `dnspython` package. Go: `dns.LookupTxt(ctx, resolver, domain)` over the
  standard-library `net.Resolver`.
- **Multi-key match semantics** — AgentPin discovery docs may carry several
  keys for rotation; a published TXT record need only match one of them.
  When the TXT carries an explicit `kid`, the matching key MUST also carry
  the same `kid`.
- **Fail-closed on mismatch** — a publisher who *intentionally* publishes a
  TXT record has signaled DNS is part of their trust chain. Divergence
  between DNS and `.well-known` indicates compromise of one channel and is
  treated as a hard failure.

#### Go SDK (fourth-language port)

- **Initial `go/` SDK** — wire-compatible with Rust, JavaScript, and Python.
  Mirrors the package layout of the SchemaPin Go SDK. Module path:
  `github.com/ThirdKeyAi/agentpin/go`.
- **Packages**: `crypto`, `jwk`, `jwt`, `types`, `discovery`, `credential`,
  `verification`, `revocation`, `pinning`, `delegation`, `mutual`, `nonce`,
  `bundle`, `resolver`, plus the new `a2a` and `dns` packages added in this
  release.
- **CLI**: `cmd/agentpin` with `keygen`, `issue`, `verify`, `bundle`
  subcommands matching the Rust binary.
- **ES256-only** enforcement implemented inline using `crypto/ecdsa`. The
  JWT verifier rejects `none`, `HS256`, `RS256`, `ES384`, and any other
  algorithm before any signature work. No third-party JWT dependency.
- **CI**: `.github/workflows/go.yml` runs `go test`, `go vet`, and
  `gofmt -l` on every PR touching `go/**`. The version-consistency check
  in `.github/workflows/release.yml` validates the Go SDK's declared
  version against the Rust/JavaScript/Python versions.

### Changed

- Cross-SDK version coordination — Rust, JavaScript, Python, and Go SDKs
  all release as **0.3.0** together. The earlier `0.3.0-alpha.1` Rust
  preview is superseded by this entry.
- **Rust MSRV bumped from 1.70 to 1.85.** Downstream ecosystem crates
  (`getrandom`, `clap_builder`, others) have moved to edition 2024 which
  requires Rust 1.85+, making the previously-declared 1.70 floor
  unbuildable from scratch in practice. The CI matrix's MSRV row now
  tests against 1.85.

### Notes

- This release is the unblock for **Symbiont v1.8.0 Phase 3** (AgentPin-
  verified AgentCards, A2A auth middleware) and **SchemaPin v1.4.0**'s
  `A2aVerificationContext` (which consumes `AllowedDomains` for tool-
  verification scoping). Both downstream releases were waiting on this
  surface.
- DNS TXT defends against HTTPS-origin compromise (compromised hosting
  account, expired domain not removed from CDN, ACME ownership-validation
  bypass) and TLS cert mis-issuance — the DNS credential chain (registrar,
  DNS provider, optionally DNSSEC) is independent of the HTTPS hosting
  chain. Spec § 4.8.3 reserved this slot in v0.1; this release ships the
  implementation across all SDKs.
- All additions are purely additive — v0.2.0 callers are unaffected.
  Discovery documents without `a2a_endpoint`, AgentCards without an
  `agentpin` extension, and absent `_agentpin` TXT records all behave
  exactly as before.

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
