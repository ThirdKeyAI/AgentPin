# AgentPin

Domain-anchored cryptographic identity for AI agents. The second layer in the [ThirdKey](https://thirdkey.ai) trust stack (SchemaPin → **AgentPin** → Symbiont).

AgentPin lets organizations publish verifiable identity documents for their AI agents, issue short-lived cryptographic credentials (JWTs), and verify agent identity using a 12-step protocol with TOFU key pinning, capability validation, delegation chains, and revocation checking.

## Protocol Overview

- **Discovery** — Organizations publish `/.well-known/agent-identity.json` declaring their agents, public keys, and capabilities
- **Credentials** — ES256 (ECDSA P-256) signed JWTs with agent identity, capabilities, constraints, and optional delegation chains
- **Verification** — 12-step flow: JWT parsing, temporal validation, discovery resolution, signature verification, revocation checking, agent status, capability/constraint validation, delegation chain verification, TOFU key pinning, and audience matching
- **Mutual Authentication** — Challenge-response protocol with 128-bit nonces for bidirectional identity verification
- **Revocation** — Credential, agent, and key-level revocation via `/.well-known/agent-identity-revocations.json`

See [AGENTPIN_TECHNICAL_SPECIFICATION.md](AGENTPIN_TECHNICAL_SPECIFICATION.md) for the full protocol spec (v0.1.0-draft).

## Project Structure

```
crates/
├── agentpin/          # Core library (publishable to crates.io)
├── agentpin-cli/      # CLI binary
└── agentpin-server/   # HTTP server for discovery/revocation endpoints
```

## Quick Start

### Generate Keys

```bash
agentpin keygen --domain example.com --kid example-2026-01 --output-dir ./keys
```

Generates `example-2026-01.private.pem`, `example-2026-01.public.pem`, and `example-2026-01.public.jwk.json`.

### Issue a Credential

```bash
agentpin issue \
  --private-key ./keys/example-2026-01.private.pem \
  --kid example-2026-01 \
  --issuer example.com \
  --agent-id "urn:agentpin:example.com:scout" \
  --capabilities "read:data,write:reports" \
  --ttl 3600
```

Outputs a signed JWT to stdout.

### Verify a Credential

Offline (with local discovery document):

```bash
agentpin verify \
  --credential <jwt> \
  --discovery ./agent-identity.json \
  --pin-store ./pins.json
```

Online (fetches discovery from issuer domain):

```bash
agentpin verify --credential <jwt>
```

Outputs a JSON verification result with validity, capabilities, key pinning status, and any errors.

### Serve Discovery Endpoints

```bash
agentpin-server \
  --discovery ./agent-identity.json \
  --revocation ./revocations.json \
  --port 8080
```

Serves:
- `GET /.well-known/agent-identity.json` (Cache-Control: max-age=3600)
- `GET /.well-known/agent-identity-revocations.json` (Cache-Control: max-age=300)
- `GET /health`

## Building

```bash
cargo build --workspace
cargo test --workspace
```

The core library has no mandatory HTTP dependency. Network fetching is behind the `fetch` feature flag:

```toml
[dependencies]
agentpin = { version = "0.1", features = ["fetch"] }
```

## Key Design Decisions

- **ES256 only** — Rejects all other JWT algorithms to prevent algorithm confusion attacks
- **Inline JWT implementation** — No external JWT crate; we control algorithm validation
- **No-redirect enforcement** — HTTP client configured with `redirect(Policy::none())` per spec security requirements
- **Feature-gated HTTP** — Core library works offline; `fetch` feature enables reqwest for network operations
- **TOFU key pinning** — Trust-on-first-use with JWK thumbprint (RFC 7638) for key continuity verification

## License

MIT - Jascha Wanger / [ThirdKey.ai](https://thirdkey.ai)
