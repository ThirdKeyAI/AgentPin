# agentpin

Domain-anchored cryptographic identity for AI agents. Part of the [ThirdKey](https://thirdkey.ai) trust stack ([SchemaPin](https://schemapin.org) → **[AgentPin](https://agentpin.org)** → [Symbiont](https://symbiont.dev)).

Requires Python >= 3.8.

## Install

```bash
pip install agentpin
```

## Quick Start

```python
from agentpin import (
    generate_key_pair,
    generate_key_id,
    pem_to_jwk,
    issue_credential,
    verify_credential_offline,
    build_discovery_document,
    KeyPinStore,
    Capability,
)

# Generate keys
private_key_pem, public_key_pem = generate_key_pair()
kid = generate_key_id(public_key_pem)
jwk = pem_to_jwk(public_key_pem, kid)

# Build discovery document
discovery = build_discovery_document(
    "example.com", "maker", [jwk],
    [{
        "agent_id": "urn:agentpin:example.com:my-agent",
        "name": "My Agent",
        "capabilities": ["read:data", "write:reports"],
        "status": "active",
    }],
    2,
)

# Issue credential
credential = issue_credential(
    private_key_pem=private_key_pem,
    kid=kid,
    issuer="example.com",
    agent_id="urn:agentpin:example.com:my-agent",
    audience="verifier.com",
    capabilities=[
        Capability.create("read", "data"),
        Capability.create("write", "reports"),
    ],
    constraints=None,
    delegation_chain=None,
    ttl_secs=3600,
)

# Verify credential
result = verify_credential_offline(
    credential_jwt=credential,
    discovery=discovery,
    revocation=None,
    pin_store=KeyPinStore(),
    audience="verifier.com",
)

if result.valid:
    print(f"Agent: {result.agent_id}")
    print(f"Capabilities: {result.capabilities}")
    print(f"Key pinning: {result.key_pinning}")
else:
    print(f"Failed: {result.error_code} - {result.error_message}")
```

## Features

- **ES256 (ECDSA P-256)** cryptographic credentials
- **Domain-anchored** `.well-known/agent-identity.json` discovery
- **12-step verification** protocol
- **Maker-deployer delegation** chains
- **Capability-scoped** credentials with constraints
- **TOFU key pinning** (compatible with SchemaPin)
- **Credential, agent, and key-level revocation**
- **Mutual authentication** with challenge-response
- **Trust bundles** for air-gapped and enterprise verification (v0.2.0)
- **Signed A2A AgentCards** (v0.3.0) — extends the [A2A](https://github.com/google-a2a/A2A) AgentCard with an AgentPin cryptographic-identity payload. `LocalAgentCardStore` for push-registered agents, `A2aAgentCardResolver` for `.well-known/agent-card.json` fetches.
- **DNS TXT cross-verification** (v0.3.0) — second-channel trust via `_agentpin.{domain}` TXT records (`v=agentpin1; kid=...; fp=sha256:<hex>`).
- **`AllowedDomains` typed wrapper** (v0.3.0) — empty-list-equals-unrestricted convention with intersection semantics for cross-protocol scoping.

## API

### Key Management

```python
generate_key_pair()              # → (private_key_pem, public_key_pem)
generate_key_id(public_key_pem)  # → kid (hex SHA-256)
pem_to_jwk(public_key_pem, kid)  # → JWK dict
jwk_to_pem(jwk)                  # → PEM string
```

### Credentials

```python
issue_credential(
    private_key_pem, kid, issuer, agent_id, audience,
    capabilities, constraints, delegation_chain, ttl_secs
)
# → compact JWT string
```

### Verification

```python
# Offline (with local discovery document)
verify_credential_offline(jwt, discovery, revocation, pin_store, audience, config)
# → VerificationResult(valid, agent_id, issuer, capabilities, key_pinning, ...)

# Online (auto-fetches discovery from issuer domain)
verify_credential(jwt, pin_store, audience, config)
```

### Discovery & Revocation

```python
build_discovery_document(entity, entity_type, public_keys, agents, max_delegation_depth)
build_revocation_document(entity)
add_revoked_credential(doc, jti, reason)
add_revoked_agent(doc, agent_id, reason)
add_revoked_key(doc, kid, reason)
```

### Mutual Authentication

```python
from agentpin import create_challenge, create_response, verify_response

challenge = create_challenge(verifier_credential)
response = create_response(challenge, private_key_pem, kid)
verify_response(response, challenge["nonce"], public_key_pem)
```

### Key Pinning

```python
from agentpin import KeyPinStore, PinningResult

store = KeyPinStore()
result = store.check_and_pin(domain, jwk)  # PinningResult.FIRST_USE | MATCHED | CHANGED
store.add_key(domain, jwk)                  # allow key rotation
json_str = store.to_json()                  # persist
restored = KeyPinStore.from_json(json_str)  # restore
```

### Trust Bundles (v0.2.0)

```python
from agentpin import (
    create_trust_bundle,
    find_bundle_discovery,
    verify_credential_with_bundle,
    save_trust_bundle,
    load_trust_bundle,
)

# Create a bundle with pre-loaded discovery documents
bundle = create_trust_bundle()
bundle["documents"].append(discovery)
bundle["revocations"].append(revocation)

# Verify without any HTTP calls
result = verify_credential_with_bundle(
    credential, bundle, pin_store=KeyPinStore(), audience="verifier.com"
)

# Save / load bundles to disk
save_trust_bundle(bundle, "trust-bundle.json")
bundle = load_trust_bundle("trust-bundle.json")
```

### Configuration

```python
from agentpin import VerifierConfig

config = VerifierConfig(
    clock_skew_secs=60,   # allow 60s time skew
    max_ttl_secs=86400,   # max 24h credential lifetime
)
```

### A2A AgentCards (v0.3.0)

```python
from agentpin import (
    build_and_sign_agent_card,
    verify_agentpin_extension,
    LocalAgentCardStore,
    A2aAgentCardResolver,
)

# Build + sign an A2A AgentCard from an AgentPin declaration
card = build_and_sign_agent_card(
    "https://example.com/agent",
    declaration,
    private_key_pem,
    "example-2026-05",
    "https://example.com/.well-known/agent-identity.json",
    streaming=True,
)

# Verify (extension signature only — pair with discovery for full chain)
verify_agentpin_extension(card)

# Push-based: register a card inline (no HTTP)
store = LocalAgentCardStore()
store.register(card)                                # verifies signature
doc = store.resolve_discovery("example.com")        # -> derived discovery dict

# Pull-based: fetch + verify over HTTPS
resolver = A2aAgentCardResolver()
fetched = resolver.resolve_discovery("example.com")
```

See [docs/a2a-agentcards.md](https://github.com/ThirdKeyAI/AgentPin/blob/main/docs/a2a-agentcards.md) for the full guide.

### DNS TXT cross-verification (v0.3.0)

```python
from agentpin import parse_txt_record, verify_dns_match, fetch_dns_txt

# Parse a TXT value retrieved out-of-band
record = parse_txt_record("v=agentpin1; kid=example-2026-05; fp=sha256:abcd...")
verify_dns_match(discovery_doc, record)             # raises DISCOVERY_INVALID on mismatch

# Or look it up live (requires the optional dnspython package)
fetched = fetch_dns_txt("example.com")              # None when no record exists
```

### AllowedDomains (v0.3.0)

```python
from agentpin import AllowedDomains

caller   = AllowedDomains.from_constraints(caller_credential.get("constraints"))
provider = AllowedDomains.from_constraints(provider_agent.get("constraints"))
scope    = AllowedDomains.intersect(caller, provider)  # unrestricted ∩ X = X
```

## Cross-Language Interoperability

Credentials and signed A2A AgentCards issued by the Python package verify byte-identically in the [Rust](https://crates.io/crates/agentpin), [JavaScript](https://www.npmjs.com/package/agentpin), and [Go](https://pkg.go.dev/github.com/ThirdKeyAi/agentpin/go) implementations, and vice versa. All four SDKs use DER-encoded ECDSA signatures, identical JSON field names, and sorted-key canonical JSON for AgentCard signing inputs.

## License

MIT — [ThirdKey.ai](https://thirdkey.ai)
