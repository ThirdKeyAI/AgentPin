# Getting Started with AgentPin

This guide walks you through installing AgentPin, generating keys, issuing your first credential, and verifying it — in Rust, JavaScript, and Python.

---

## Installation

### Rust

Add `agentpin` to your `Cargo.toml`:

```toml
[dependencies]
agentpin = "0.2"
```

For online discovery (fetches `.well-known` documents over HTTPS), enable the `fetch` feature:

```toml
[dependencies]
agentpin = { version = "0.2", features = ["fetch"] }
```

Build and test:

```bash
cargo build
cargo test
```

### JavaScript

Requires Node.js >= 18. Zero external dependencies.

```bash
npm install agentpin
```

### Python

Requires Python >= 3.8.

```bash
pip install agentpin
```

### CLI

Build the CLI from the Rust workspace:

```bash
cargo install --path crates/agentpin-cli
```

This gives you the `agentpin` command for key generation, credential issuance, and verification.

---

## Step 1: Generate a Key Pair

AgentPin uses ES256 (ECDSA P-256) exclusively. Generate a keypair in any language:

### Rust

```rust
use agentpin::{generate_key_pair, pem_to_jwk};

let keys = generate_key_pair()?;
// keys.private_key_pem — PEM-encoded private key
// keys.public_key_pem  — PEM-encoded public key

let kid = "my-key-2026-01";
let jwk = pem_to_jwk(&keys.public_key_pem, kid)?;
```

### JavaScript

```javascript
import { generateKeyPair, generateKeyId, pemToJwk } from 'agentpin';

const { privateKeyPem, publicKeyPem } = generateKeyPair();
const kid = generateKeyId(publicKeyPem);
const jwk = pemToJwk(publicKeyPem, kid);
```

### Python

```python
from agentpin import generate_key_pair, generate_key_id, pem_to_jwk

private_key_pem, public_key_pem = generate_key_pair()
kid = generate_key_id(public_key_pem)
jwk = pem_to_jwk(public_key_pem, kid)
```

### CLI

```bash
agentpin keygen \
  --domain example.com \
  --kid example-2026-01 \
  --output-dir ./keys
```

This generates three files:
- `example-2026-01.private.pem` — Private key (keep secret)
- `example-2026-01.public.pem` — Public key
- `example-2026-01.public.jwk.json` — Public key in JWK format

---

## Step 2: Build a Discovery Document

A discovery document declares your organization's agents, public keys, and capabilities. It is published at `/.well-known/agent-identity.json`.

### JavaScript

```javascript
import { buildDiscoveryDocument } from 'agentpin';

const discovery = buildDiscoveryDocument(
    'example.com',      // entity domain
    'maker',            // entity_type: 'maker' | 'deployer' | 'both'
    [jwk],              // array of public key JWKs
    [{
        agent_id: 'urn:agentpin:example.com:my-agent',
        name: 'My Agent',
        capabilities: ['read:data', 'write:reports'],
        status: 'active',
    }],
    2,                  // max delegation depth
    new Date().toISOString(),
);
```

### Python

```python
from agentpin import build_discovery_document

discovery = build_discovery_document(
    "example.com",
    "maker",
    [jwk],
    [{
        "agent_id": "urn:agentpin:example.com:my-agent",
        "name": "My Agent",
        "capabilities": ["read:data", "write:reports"],
        "status": "active",
    }],
    2,
)
```

### Discovery Document Structure

```json
{
  "agentpin_version": "0.1",
  "entity": "example.com",
  "entity_type": "maker",
  "public_keys": [
    {
      "kid": "example-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "sig",
      "key_ops": ["verify"]
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:example.com:my-agent",
      "name": "My Agent",
      "capabilities": ["read:data", "write:reports"],
      "status": "active"
    }
  ],
  "revocation_endpoint": "https://example.com/.well-known/agent-identity-revocations.json",
  "max_delegation_depth": 2,
  "updated_at": "2026-02-15T00:00:00Z"
}
```

---

## Step 3: Issue a Credential

Credentials are ES256-signed JWTs that assert agent identity, capabilities, and constraints.

### Rust

```rust
use agentpin::{issue_credential, Capability};

let credential = issue_credential(
    &keys.private_key_pem,
    "example-2026-01",                          // kid
    "example.com",                               // issuer domain
    "urn:agentpin:example.com:my-agent",        // agent_id
    Some("verifier.com"),                        // audience (optional)
    &[Capability::new("read:data"), Capability::new("write:reports")],
    None,                                        // constraints
    None,                                        // delegation chain
    3600,                                        // TTL in seconds
)?;
// credential is a compact JWT string: header.payload.signature
```

### JavaScript

```javascript
import { issueCredential, Capability } from 'agentpin';

const credential = issueCredential(
    privateKeyPem,
    kid,
    'example.com',
    'urn:agentpin:example.com:my-agent',
    'verifier.com',
    [new Capability('read:data'), new Capability('write:reports')],
    null,   // constraints
    null,   // delegation chain
    3600,   // TTL in seconds
);
```

### Python

```python
from agentpin import issue_credential, Capability

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
```

### CLI

```bash
agentpin issue \
  --private-key ./keys/example-2026-01.private.pem \
  --kid example-2026-01 \
  --issuer example.com \
  --agent-id "urn:agentpin:example.com:my-agent" \
  --capabilities "read:data,write:reports" \
  --ttl 3600
```

---

## Step 4: Verify a Credential

Verification follows a 12-step protocol. You can verify offline (with a local discovery document) or online (auto-fetching from the issuer's domain).

### Offline Verification

Offline verification is the recommended approach — it works without HTTP calls and is deterministic.

#### JavaScript

```javascript
import { verifyCredentialOffline, KeyPinStore } from 'agentpin';

const result = verifyCredentialOffline(
    credential,
    discovery,
    null,                // revocation document (optional)
    new KeyPinStore(),   // TOFU pin store
    'verifier.com',      // expected audience
    { clockSkewSecs: 60, maxTtlSecs: 86400 },
);

if (result.valid) {
    console.log('Agent:', result.agent_id);
    console.log('Issuer:', result.issuer);
    console.log('Capabilities:', result.capabilities);
    console.log('Key pinning:', result.key_pinning); // 'first_use' | 'matched'
} else {
    console.error('Verification failed:', result.error_code, result.error_message);
}
```

#### Python

```python
from agentpin import verify_credential_offline, KeyPinStore

result = verify_credential_offline(
    credential_jwt=credential,
    discovery=discovery,
    revocation=None,
    pin_store=KeyPinStore(),
    audience="verifier.com",
)

if result.valid:
    print(f"Agent: {result.agent_id}")
    print(f"Issuer: {result.issuer}")
    print(f"Capabilities: {result.capabilities}")
    print(f"Key pinning: {result.key_pinning}")
else:
    print(f"Failed: {result.error_code} - {result.error_message}")
```

### Online Verification

Online verification auto-fetches the discovery document from the issuer's domain.

#### JavaScript

```javascript
import { verifyCredential, KeyPinStore } from 'agentpin';

const result = await verifyCredential(
    credential,
    new KeyPinStore(),
    'verifier.com',
);
```

#### Python

```python
from agentpin import verify_credential, KeyPinStore

result = verify_credential(
    credential_jwt=credential,
    pin_store=KeyPinStore(),
    audience="verifier.com",
)
```

#### CLI

```bash
# Online verification
agentpin verify --credential <jwt>

# Offline verification
agentpin verify \
  --credential <jwt> \
  --discovery ./agent-identity.json \
  --pin-store ./pins.json
```

---

## Step 5: Set Up Revocation

Build a revocation document to revoke credentials, agents, or keys:

### JavaScript

```javascript
import {
    buildRevocationDocument,
    addRevokedCredential,
    addRevokedAgent,
    addRevokedKey,
} from 'agentpin';

const revocation = buildRevocationDocument('example.com');

// Revoke a specific credential by JTI
addRevokedCredential(revocation, 'credential-jti-123', 'key_compromise');

// Revoke an agent entirely
addRevokedAgent(revocation, 'urn:agentpin:example.com:old-agent', 'decommissioned');

// Revoke a key
addRevokedKey(revocation, 'example-2025-01', 'key_compromise');
```

### Python

```python
from agentpin import (
    build_revocation_document,
    add_revoked_credential,
    add_revoked_agent,
    add_revoked_key,
)

revocation = build_revocation_document("example.com")
add_revoked_credential(revocation, "credential-jti-123", "key_compromise")
add_revoked_agent(revocation, "urn:agentpin:example.com:old-agent", "decommissioned")
add_revoked_key(revocation, "example-2025-01", "key_compromise")
```

Publish the revocation document at `/.well-known/agent-identity-revocations.json`.

---

## Next Steps

- [Verification Flow](verification-flow.md) — Understand the 12-step verification protocol
- [CLI Guide](cli-guide.md) — Full CLI reference
- [Trust Bundles](trust-bundles.md) — Offline and air-gapped verification
- [Delegation Chains](delegation-chains.md) — Maker-deployer delegation patterns
- [Deployment](deployment.md) — Serve `.well-known` endpoints in production
- [Security Best Practices](security.md) — Key management and threat model
