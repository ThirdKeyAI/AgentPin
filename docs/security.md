# Security Best Practices

This guide covers the security model, threat mitigations, and operational best practices for AgentPin deployments.

---

## Cryptographic Foundation

AgentPin uses **ES256 (ECDSA with P-256)** exclusively. All other algorithms are rejected.

| Property | Value |
|----------|-------|
| Signing Algorithm | ECDSA (Elliptic Curve Digital Signature Algorithm) |
| Curve | P-256 (secp256r1) |
| Hash | SHA-256 |
| Key Format | JWK (RFC 7517) for public keys, PEM for private keys |
| Credential Format | JWT (compact serialization) |
| Signature Encoding | DER-encoded (cross-language compatible) |

### Why ES256 Only

Single-algorithm enforcement prevents:

- **Algorithm confusion attacks** — Attacker substitutes `none` or `HS256` to bypass verification
- **Downgrade attacks** — Attacker forces weaker algorithm selection
- **Implementation complexity** — Fewer code paths means fewer bugs

All three implementations (Rust, JavaScript, Python) validate `alg: "ES256"` before any other processing.

---

## Key Management

### Private Key Security

- **Never commit private keys** to version control
- **Never embed private keys** in application code or environment variables in plaintext
- Store private keys in secure storage: file system with restricted permissions, HSM, or secrets manager
- Use separate keys for separate environments (dev, staging, production)

```bash
# Set restrictive permissions on private key files
chmod 600 ./keys/*.private.pem

# Verify permissions
ls -la ./keys/*.private.pem
# -rw------- 1 agentpin agentpin 227 Feb 15 2026 example-2026-01.private.pem
```

### Key Rotation

Rotate keys regularly. Recommended schedule:

| Key Type | Rotation Period |
|----------|----------------|
| Production signing keys | Every 6-12 months |
| Development/testing keys | Every 3 months |
| Keys after suspected compromise | Immediately |

**Rotation procedure:**

1. Generate new key pair
2. Add new public key to discovery document
3. Reduce discovery document cache TTL during transition
4. Begin issuing credentials with new key
5. After grace period, revoke old key
6. Remove old key from discovery document

### Key ID Naming Convention

Use descriptive, time-stamped key IDs for traceability:

```
{domain}-{year}-{sequence}

Examples:
  example-2026-01       # First key for 2026
  example-2026-02       # Second key (after rotation)
  staging-2026-01       # Staging environment key
```

---

## Credential Security

### Short-Lived Credentials

Issue credentials with the shortest practical TTL:

| Use Case | Recommended TTL |
|----------|----------------|
| Single API call | 300 seconds (5 min) |
| Session | 3600 seconds (1 hour) |
| Long-running task | 14400 seconds (4 hours) |
| Maximum allowed | 86400 seconds (24 hours) |

```python
# Prefer short TTLs
credential = issue_credential(
    private_key_pem=key,
    kid="example-2026-01",
    issuer="example.com",
    agent_id="urn:agentpin:example.com:agent",
    audience="verifier.com",
    capabilities=[Capability.create("read", "data")],
    ttl_secs=3600,  # 1 hour — not 86400
)
```

### Audience Binding

Always specify an audience (`aud` claim) to prevent credential replay at unintended verifiers:

```javascript
const credential = issueCredential(
    privateKey, kid, 'example.com',
    'urn:agentpin:example.com:agent',
    'verifier.com',  // Bind to specific verifier
    capabilities, null, null, 3600,
);
```

Verifiers should check the audience:

```javascript
const result = verifyCredentialOffline(
    credential, discovery, null, pinStore,
    'verifier.com',  // Reject if aud doesn't match
);
```

### Capability Scoping

Follow the principle of least privilege — issue credentials with only the capabilities needed:

```python
# Good: Minimal capabilities for the task
credential = issue_credential(
    ...,
    capabilities=[Capability.create("read", "reports")],
    ttl_secs=300,
)

# Bad: Overly broad capabilities
credential = issue_credential(
    ...,
    capabilities=[Capability.create("read", "*"), Capability.create("write", "*")],
    ttl_secs=86400,
)
```

---

## TOFU Key Pinning

Trust-On-First-Use pinning protects against key substitution attacks after initial verification.

### How It Works

1. First verification for a domain: public key fingerprint (JWK thumbprint per RFC 7638) is stored
2. Subsequent verifications: key must match the stored fingerprint
3. Key change detected: verification fails with `key_changed` error

### Pin Store Persistence

Always persist the pin store between sessions:

```python
import os
from agentpin import KeyPinStore

PIN_FILE = "/var/lib/agentpin/pins.json"

# Load existing pins
if os.path.exists(PIN_FILE):
    pin_store = KeyPinStore.from_json(open(PIN_FILE).read())
else:
    pin_store = KeyPinStore()

# Use for verification
result = verify_credential_offline(jwt, discovery, None, pin_store, audience)

# Save updated pins
with open(PIN_FILE, "w") as f:
    f.write(pin_store.to_json())
```

### Handling Key Changes

A `key_changed` result requires investigation:

```python
if result.key_pinning == "changed":
    # This is a security event — do not silently accept
    log_security_event(
        event="key_changed",
        domain=result.issuer,
        action="verification_rejected",
    )
    # Require manual approval before accepting the new key
```

Legitimate key changes (rotation) should be communicated out-of-band. Update the pin store explicitly:

```javascript
const pinStore = KeyPinStore.fromJson(existingPins);
// After confirming legitimate rotation:
pinStore.addKey(domain, newJwk);
```

---

## Threat Model

### Agent Impersonation

**Threat:** A malicious agent claims to be a trusted agent.

**Mitigation:** Cryptographic verification — the agent must present a JWT signed by a key declared in the issuer's discovery document. Without the private key, impersonation is impossible.

### Unauthorized Delegation

**Threat:** An agent claims authorization from an operator who never granted it.

**Mitigation:** Delegation chains require a `maker_attestation` — a cryptographic signature from the Maker. The Deployer cannot forge this without the Maker's private key.

### Capability Inflation

**Threat:** An agent claims capabilities beyond what it was authorized.

**Mitigation:** Capability validation (Step 10) checks that credential capabilities are a subset of capabilities declared in the discovery document. Delegation chains enforce capability narrowing at each level.

### Discovery Document Tampering

**Threat:** An attacker modifies the discovery document in transit or at the server.

**Mitigation:**
- HTTPS provides transport-layer integrity
- TOFU pinning detects key changes after initial verification
- Redirect rejection prevents redirect-based attacks

### Replay Attacks

**Threat:** An attacker captures and replays a valid credential.

**Mitigation:**
- Short-lived credentials minimize the replay window
- Audience binding prevents replay at unintended verifiers
- JTI (JWT ID) enables one-time-use verification
- Nonce-based mutual authentication for real-time verification

### Key Compromise

**Threat:** An attacker obtains a private key.

**Mitigation:**
- Revocation at credential, agent, and key levels
- Short credential TTLs limit exposure window
- TOFU pinning detects key substitution at verifiers that already pinned the legitimate key

---

## Revocation

### Three Levels of Revocation

| Level | Scope | Use Case |
|-------|-------|----------|
| Credential | Single JWT (by `jti`) | Compromised individual credential |
| Agent | All credentials for an agent | Agent decommissioned or compromised |
| Key | All credentials signed by a key | Key compromised |

### Revocation Document

Publish at `/.well-known/agent-identity-revocations.json` with a short cache TTL (5 minutes):

```json
{
  "agentpin_version": "0.1",
  "entity": "example.com",
  "revoked_credentials": [
    { "id": "jti-123", "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z" }
  ],
  "revoked_agents": [],
  "revoked_keys": [
    { "id": "example-2025-01", "reason": "key_compromise", "revoked_at": "2026-02-15T00:00:00Z" }
  ],
  "updated_at": "2026-02-15T00:00:00Z"
}
```

### Revocation Checking

Verifiers MUST check revocation on every verification, regardless of discovery document cache state.

---

## Network Security

### HTTPS Requirements

- Discovery documents MUST be served over HTTPS
- TLS certificates MUST be valid (not expired, not self-signed in production)
- HTTP redirects MUST NOT be followed during discovery document fetching

### No-Redirect Policy

AgentPin rejects HTTP redirects to prevent:

- Redirect to attacker-controlled server serving malicious discovery document
- Redirect loops causing denial of service
- Open redirect exploitation

```javascript
// Correct: reject redirects
const response = await fetch(url, { redirect: 'error' });

// Incorrect: following redirects
const response = await fetch(url, { redirect: 'follow' }); // DO NOT DO THIS
```

### Rate Limiting

Protect discovery endpoints from abuse:

```nginx
# nginx rate limiting for AgentPin endpoints
limit_req_zone $binary_remote_addr zone=agentpin:10m rate=10r/s;

location /.well-known/agent-identity.json {
    limit_req zone=agentpin burst=20 nodelay;
    # ... other config
}
```

---

## Cross-Language Interoperability

All three AgentPin implementations (Rust, JavaScript, Python) produce interoperable credentials:

- All use DER-encoded ECDSA signatures
- All use identical JSON field names
- A credential issued by one language can be verified by any other

Verify cross-language compatibility in your test suite:

```bash
# Issue with Python, verify with JavaScript
python -c "from agentpin import ...; print(issue_credential(...))" | \
  node -e "const { verifyCredentialOffline } = require('agentpin'); ..."
```
