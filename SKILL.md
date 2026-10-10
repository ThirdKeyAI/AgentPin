---
name: agentpin
title: AgentPin
description: Domain-anchored cryptographic identity protocol for AI agents — ES256 JWT credentials, 12-step verification, TOFU key pinning, revocation, delegation chains, mutual authentication, and (v0.3.0, four-language parity) A2A AgentCard extension types + signed AgentCard builder + LocalAgentCardStore + A2aAgentCardResolver + AllowedDomains type for cross-protocol use with SchemaPin v1.4, plus DNS TXT cross-verification at _agentpin.{domain} for second-channel trust independent of HTTPS hosting
version: 0.3.0
stable_version: 0.3.0
---

# AgentPin Development Skills Guide

**Purpose**: This guide helps AI assistants work with AgentPin for domain-anchored cryptographic agent identity verification.

**For Full Documentation**: See the [README](https://github.com/ThirdKeyAI/agentpin/blob/main/README.md) and [Technical Specification](https://github.com/ThirdKeyAI/agentpin/blob/main/AGENTPIN_TECHNICAL_SPECIFICATION.md).

## What AgentPin Does

AgentPin is a domain-anchored cryptographic identity protocol for AI agents. It enables organizations to publish verifiable identity documents for their agents, issue short-lived JWT credentials, and verify agent identity through a multi-step protocol including TOFU key pinning, revocation checking, and delegation chains.

**Part of the ThirdKey trust stack**: SchemaPin (tool integrity) → AgentPin (agent identity) → Symbiont (runtime)

---

## Architecture

```
Organization                         Verifying Party
────────────                         ───────────────
1. Generate ECDSA P-256 keypair
2. Publish agent identity at          3. Discover identity from
   /.well-known/agent-identity.json      /.well-known/agent-identity.json
4. Issue JWT credential               5. Verify credential (12-step flow)
   (ES256 signed, short-lived)           - JWT parsing & ES256 verification
                                         - Domain binding check
                                         - TOFU key pinning
                                         - Revocation checking
                                         - Capability validation
                                         - Delegation chain verification
```

---

## Project Structure

```
crates/
├── agentpin/          Core library (no mandatory HTTP dep)
├── agentpin-cli/      CLI binary (keygen, issue, verify, bundle)
└── agentpin-server/   Axum server for .well-known endpoints
```

---

## Quick Start by Language

### Rust (CLI)

```bash
# Generate keys
cargo run -p agentpin-cli -- keygen \
    --output-dir ./keys --agent-name "my-agent"

# Issue a credential (ES256 JWT, 1-hour TTL)
cargo run -p agentpin-cli -- issue \
    --key ./keys/my-agent.private.pem \
    --issuer "https://example.com" \
    --agent-id "my-agent" \
    --capabilities read,write --ttl 3600

# Verify offline
cargo run -p agentpin-cli -- verify \
    --credential ./credential.jwt \
    --discovery ./agent-identity.json

# Verify online (fetches from .well-known)
cargo run -p agentpin-cli -- verify \
    --credential ./credential.jwt --domain example.com

# Create trust bundle for air-gapped environments
cargo run -p agentpin-cli -- bundle \
    --discovery ./agent-identity.json \
    --revocation ./revocations.json --output ./bundle.json
```

### Rust (Library)

```rust
use agentpin::{
    credential::issue_credential,
    crypto::{generate_key_pair, load_signing_key},
    pinning::KeyPinStore,
    types::capability::Capability,
    verification::{verify_credential_offline, VerifierConfig},
};

let kp = generate_key_pair()?;
let sk = load_signing_key(&kp.private_key_pem)?;

let jwt = issue_credential(
    &sk, "example-2026-01", "example.com",
    "urn:agentpin:example.com:my-agent", Some("verifier.com"),
    vec![Capability::from("read:data")], None, None, 3600,
)?;

let mut pin_store = KeyPinStore::new();
let result = verify_credential_offline(
    &jwt, &discovery_doc, Some(&revocation_doc), &mut pin_store,
    Some("verifier.com"), &VerifierConfig::default(),
);
assert!(result.valid);
```

### JavaScript

```bash
npm install agentpin
```

```javascript
import {
    generateKeyPair, issueCredential, verifyCredentialOffline,
    KeyPinStore, Capability,
} from 'agentpin';

const { privateKeyPem } = generateKeyPair();

const jwt = issueCredential(
    privateKeyPem, 'example-2026-01', 'example.com',
    'urn:agentpin:example.com:my-agent', 'verifier.com',
    [new Capability('read:data')], null, null, 3600,
);

const pinStore = new KeyPinStore();
const result = verifyCredentialOffline(jwt, discoveryDoc, revocationDoc, pinStore, 'verifier.com');
```

### Python

```bash
pip install agentpin
```

```python
from agentpin.capability import Capability
from agentpin.credential import issue_credential
from agentpin.crypto import generate_key_pair
from agentpin.pinning import KeyPinStore
from agentpin.verification import verify_credential_offline

private_pem, public_pem = generate_key_pair()

jwt = issue_credential(
    private_pem, "example-2026-01", "example.com",
    "urn:agentpin:example.com:my-agent", "verifier.com",
    [Capability("read:data")], None, None, 3600,
)

pin_store = KeyPinStore()
result = verify_credential_offline(jwt, discovery_doc, revocation_doc, pin_store, "verifier.com")
```

### Go

```bash
go get github.com/ThirdKeyAi/agentpin/go
go install github.com/ThirdKeyAi/agentpin/go/cmd/agentpin@latest
```

```go
import (
    "github.com/ThirdKeyAi/agentpin/go/pkg/credential"
    "github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
    "github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
    "github.com/ThirdKeyAi/agentpin/go/pkg/types"
    "github.com/ThirdKeyAi/agentpin/go/pkg/verification"
)

kp, _ := crypto.GenerateKeyPair()
priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)

cred, _ := credential.IssueCredential(
    priv, "my-key-2026", "example.com",
    "urn:agentpin:example.com:my-agent",
    "verifier.com",
    []types.Capability{"read:data", "write:report"},
    nil, nil, 3600,
)

pinStore := pinning.NewKeyPinStore()
result := verification.VerifyCredentialOffline(
    cred, discoveryDoc, nil, pinStore,
    "verifier.com", verification.DefaultVerifierConfig(),
)
```

### Serve .well-known Endpoints

```bash
cargo run -p agentpin-server -- \
    --identity ./agent-identity.json \
    --revocation ./revocations.json \
    --port 3000
```

Serves:
- `GET /.well-known/agent-identity.json` (Cache-Control: max-age=3600)
- `GET /.well-known/agent-identity-revocations.json` (Cache-Control: max-age=300)
- `GET /health`

---

## Core Library API

### Key Modules

| Module | Purpose |
|--------|---------|
| `crypto` | ECDSA P-256 signing/verification (no external JWT crate) |
| `types` | Core data structures (agents, credentials, capabilities) |
| `credential` | JWT issuance and parsing |
| `discovery` | Publishing and resolving agent identity documents |
| `verification` | 12-step credential validation flow |
| `revocation` | Checking revoked credentials/agents/keys |
| `pinning` | TOFU key pinning with JWK thumbprints |
| `delegation` | Delegation chain validation |
| `mutual` | Challenge-response mutual authentication (128-bit nonces) |
| `jwk` | JWK handling and thumbprint computation |
| `resolver` | Pluggable discovery resolution |

### Language API Reference

| Operation | Rust | JavaScript | Python | Go |
|-----------|------|------------|--------|-----|
| Generate keys | `crypto::generate_key_pair()` | `generateKeypair()` | `generate_keypair()` | `crypto.GenerateKeyPair()` |
| Issue credential | `credential::issue_credential()` | `issueCredential()` | `issue_credential()` | `credential.IssueCredential()` |
| Verify credential | `verification::verify_credential_offline()` | `verifyCredentialOffline()` | `verify_credential_offline()` | `verification.VerifyCredentialOffline()` |
| Key pinning | `KeyPinStore` | `KeyPinStore` | `KeyPinStore` | `pinning.KeyPinStore` |
| Trust bundle | `TrustBundle::new()` | `new TrustBundle()` | `TrustBundle()` | `bundle.NewTrustBundle()` |
| Mutual auth | `mutual::create_challenge()` | `createChallenge()` | `create_challenge()` | `mutual.CreateChallenge()` |

### Feature Flags

| Feature | Purpose |
|---------|---------|
| `fetch` | Enables HTTP via reqwest for online discovery |
| (default) | Core library with no HTTP dependency |

---

## Key Concepts

### ES256 Only

AgentPin exclusively uses ES256 (ECDSA P-256). All other algorithms are rejected. This is enforced inline without an external JWT crate.

### 12-Step Verification

The credential verification flow includes:
1. JWT structure parsing
2. Header algorithm validation (ES256 only)
3. Signature verification
4. Issuer domain extraction
5. Discovery document resolution
6. Domain binding verification
7. Key matching (issuer key vs discovery)
8. TOFU key pinning check
9. Expiration validation
10. Revocation checking
11. Capability validation
12. Delegation chain verification (if present)

### TOFU Key Pinning

Pins are keyed by the normalized domain (lowercase, trailing dot removed,
IDNA). On first verification every key in the validated discovery document is
pinned. A credential signed by an unpinned key is accepted only when the
document still lists a pinned key (rotation continuity,
`key_pinning.status: "rotated"`); otherwise it fails with `KEY_PIN_MISMATCH`.

### Delegation Chains

Delegation chains are verified by default (`require_delegation_verification`):
each attestation is checked against the attester's discovery document,
capabilities only narrow down the chain, depth limits are respected, and a
chain that cannot be verified rejects the credential.

### Mutual Authentication

Challenge-response with 128-bit nonces (22 base64url characters), single-use
by default. Responses sign a domain-separated structure bound to the nonce,
timestamp, responder `kid` and the verifier's credential, never raw bytes.

### Security Defaults (0.4.0, unreleased)

- Every non-JWT signature uses a domain-separated input
  (`context || 0x00 || length-prefixed fields`).
- `allowed_domains`: absent = unrestricted, `[]` = nothing.
- `credential_ttl_max` enforced (default 86400 s); malformed claims fail with
  `MALFORMED_CREDENTIAL`.
- Fetches: HTTPS only, no redirects, 10 s timeout, 1 MiB cap.
- Revocation falls back to the default `.well-known` URL; signed revocation
  documents and trust bundles are supported.

---

## Discovery Document Format

Published at `/.well-known/agent-identity.json`:

```json
{
    "agentpin_version": "0.1",
    "entity": "example.com",
    "entity_type": "maker",
    "public_keys": [ { "kid": "example-2026-01", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "sig" } ],
    "agents": [
        {
            "agent_id": "urn:agentpin:example.com:my-agent",
            "name": "My Agent",
            "description": "A helpful agent",
            "capabilities": ["read:data", "write:report"],
            "constraints": {
                "allowed_domains": ["*.partner.com"],
                "data_classification_max": "internal",
                "rate_limit": "100/hour"
            },
            "credential_ttl_max": 3600,
            "status": "active",
            "directory_listing": true
        }
    ],
    "max_delegation_depth": 2,
    "updated_at": "2026-01-15T00:00:00Z",
    "revocation_endpoint": "https://example.com/.well-known/agent-identity-revocations.json"
}
```

---

## v0.2.0 Features

### Trust Bundles (Offline / Air-Gapped)

Pre-package discovery + revocation data for environments without internet:

```python
from agentpin.bundle import TrustBundle

bundle = TrustBundle.from_json(bundle_json_str)
discovery = bundle.find_discovery("example.com")
revocation = bundle.find_revocation("example.com")
```

### Pluggable Discovery Resolvers

```python
from agentpin.discovery import (
    WellKnownResolver,    # HTTP .well-known lookups
    DnsTxtResolver,       # DNS TXT record lookups
    ManualResolver,       # Pre-configured discovery data
)
```

### Directory Listing

Domains can advertise all their agents via `"directory_listing": true` in the discovery document. Verifiers can enumerate available agents before issuing challenges.

---

## Development

### Build and Test

```bash
# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Lint
cargo clippy --workspace

# Format check
cargo fmt --check
```

### Conventions

- Rust edition 2021, MSRV 1.70
- `cargo clippy --workspace` must pass with zero warnings
- `cargo fmt --check` must pass
- Inline tests in source files (`#[cfg(test)] mod tests`)
- ES256 only — reject all other algorithms
- Feature-gated HTTP: `fetch` feature enables reqwest

---

## Pro Tips for AI Assistants

1. **ES256 only** — never accept RS256, HS256, or any other algorithm
2. **Short-lived credentials** — prefer TTLs of hours, not days
3. **Always check revocation** before trusting a credential
4. **TOFU pinning** means first-seen key is trusted — warn on key changes
5. **Delegation chains** should narrow capabilities, never widen them
6. **No external JWT crate** — algorithm validation is controlled inline to prevent algorithm confusion attacks
7. **Feature-gate HTTP** — use the `fetch` feature only when online discovery is needed; default is offline-capable
8. **Cross-compatible with SchemaPin** — both use ECDSA P-256, same crypto primitives
9. **Trust bundles** are ideal for CI/CD and air-gapped deployments — pre-package discovery + revocation data
10. **JavaScript, Python, and Go SDKs** provide identical verification guarantees to the Rust crate
