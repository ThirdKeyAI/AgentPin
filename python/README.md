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

### Configuration

```python
from agentpin import VerifierConfig

config = VerifierConfig(
    clock_skew_secs=60,   # allow 60s time skew
    max_ttl_secs=86400,   # max 24h credential lifetime
)
```

## Cross-Language Interoperability

Credentials issued by the Python package can be verified by the [Rust](https://crates.io/crates/agentpin) and [JavaScript](https://www.npmjs.com/package/agentpin) implementations, and vice versa. All implementations use DER-encoded ECDSA signatures and identical JSON field names.

## License

MIT — [ThirdKey.ai](https://thirdkey.ai)
