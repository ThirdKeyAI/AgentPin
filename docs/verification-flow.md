# The 12-Step Verification Flow

AgentPin verifies agent credentials through a comprehensive 12-step protocol. This guide explains each step, shows how to implement custom verification logic, and covers error handling.

---

## Overview

When a verifier receives an AgentPin credential (JWT), it performs these steps in order:

| Step | Name | Failure Mode |
|------|------|-------------|
| 1 | JWT Parsing | `invalid_format` — malformed JWT structure |
| 2 | Algorithm Check | `invalid_algorithm` — must be ES256 |
| 3 | Temporal Validation | `expired` or `not_yet_valid` — check `exp`, `iat`, `nbf` |
| 4 | Discovery Resolution | `discovery_failed` — cannot fetch/resolve discovery document |
| 5 | Signature Verification | `invalid_signature` — ECDSA signature does not match |
| 6 | Domain Binding | `domain_mismatch` — issuer domain doesn't match discovery entity |
| 7 | Key Matching | `key_not_found` — `kid` not in discovery document's public keys |
| 8 | Agent Status | `agent_inactive` — agent not declared or status is not `active` |
| 9 | Revocation Checking | `revoked` — credential, agent, or key is revoked |
| 10 | Capability Validation | `capability_mismatch` — claimed capabilities exceed declared |
| 11 | Delegation Chain | `delegation_invalid` — chain verification failure |
| 12 | TOFU Key Pinning | `key_changed` — key doesn't match previously pinned key |

---

## Step-by-Step Explanation

### Step 1: JWT Parsing

The credential is a compact JWT with three Base64url-encoded segments: `header.payload.signature`.

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUtMjAyNi0wMSJ9.
eyJpc3MiOiJleGFtcGxlLmNvbSIsInN1YiI6InVybjphZ2VudHBpbjpleGFtcGxlLmNvbTp...
MEUCIQD7y2F8...
```

The parser splits on `.`, Base64url-decodes each segment, and validates the JSON structure.

**Header fields:**
- `alg` — Algorithm (must be `ES256`)
- `typ` — Type (must be `JWT`)
- `kid` — Key ID (references a key in the discovery document)

**Payload fields:**
- `iss` — Issuer domain (e.g., `example.com`)
- `sub` — Agent ID URN (e.g., `urn:agentpin:example.com:my-agent`)
- `aud` — Audience domain (optional)
- `iat` — Issued-at timestamp (Unix epoch)
- `exp` — Expiration timestamp (Unix epoch)
- `jti` — JWT ID (unique credential identifier)
- `capabilities` — Array of capability strings
- `constraints` — Object with constraint fields
- `delegation_chain` — Array of delegation attestations

### Step 2: Algorithm Check

AgentPin mandates ES256 (ECDSA with P-256) exclusively. Any other algorithm is immediately rejected. This prevents algorithm confusion attacks where an attacker substitutes a weaker algorithm.

```javascript
// The verifier checks:
if (header.alg !== 'ES256') {
    return { valid: false, error_code: 'invalid_algorithm' };
}
```

### Step 3: Temporal Validation

The verifier checks three timestamps:

```python
import time

now = time.time()
clock_skew = 60  # configurable, default 60 seconds

# Check not expired
if payload["exp"] < now - clock_skew:
    raise VerificationError("expired")

# Check issued-at is not in the future
if payload["iat"] > now + clock_skew:
    raise VerificationError("not_yet_valid")

# Check TTL doesn't exceed maximum
ttl = payload["exp"] - payload["iat"]
if ttl > max_ttl_secs:
    raise VerificationError("ttl_exceeded")
```

**Best practice:** Use short-lived credentials (hours, not days). The default maximum TTL is 86400 seconds (24 hours).

### Step 4: Discovery Resolution

The verifier extracts the `iss` (issuer) claim and resolves the discovery document. Resolution can happen via:

1. **Online** — Fetch `https://{iss}/.well-known/agent-identity.json` over HTTPS
2. **Offline** — Use a pre-provided discovery document
3. **Trust bundle** — Look up the domain in a pre-loaded trust bundle
4. **Local file** — Read from a local directory (`{domain}.json`)

```javascript
// Online resolution
const response = await fetch(
    `https://${issuer}/.well-known/agent-identity.json`,
    { redirect: 'error' }  // MUST NOT follow redirects
);
const discovery = await response.json();
```

HTTP redirects are rejected to prevent redirect-based attacks.

### Step 5: Signature Verification

The verifier resolves the public key using the `kid` from the JWT header, then verifies the ES256 signature over the `header.payload` portion of the JWT.

```python
from agentpin.crypto import verify_es256

# Find the public key matching the kid
public_key = None
for key in discovery["public_keys"]:
    if key["kid"] == header["kid"]:
        public_key = key
        break

if public_key is None:
    raise VerificationError("key_not_found")

# Verify the ECDSA signature
signing_input = f"{encoded_header}.{encoded_payload}"
is_valid = verify_es256(public_key, signing_input, signature)
```

### Step 6: Domain Binding

The `iss` claim in the JWT must match the `entity` field in the discovery document:

```javascript
if (payload.iss !== discovery.entity) {
    return { valid: false, error_code: 'domain_mismatch' };
}
```

### Step 7: Key Matching

The `kid` from the JWT header must reference a key declared in the discovery document's `public_keys` array.

### Step 8: Agent Status

The `sub` (agent_id) claim must reference an agent declared in the discovery document with `status: "active"`:

```python
agent = None
for a in discovery["agents"]:
    if a["agent_id"] == payload["sub"]:
        agent = a
        break

if agent is None or agent["status"] != "active":
    raise VerificationError("agent_inactive")
```

### Step 9: Revocation Checking

The verifier checks the revocation document (if available) for three revocation types:

```javascript
// Check credential-level revocation (by jti)
if (revocation.revoked_credentials?.some(r => r.id === payload.jti)) {
    return { valid: false, error_code: 'revoked' };
}

// Check agent-level revocation
if (revocation.revoked_agents?.some(r => r.id === payload.sub)) {
    return { valid: false, error_code: 'revoked' };
}

// Check key-level revocation
if (revocation.revoked_keys?.some(r => r.id === header.kid)) {
    return { valid: false, error_code: 'revoked' };
}
```

### Step 10: Capability Validation

Capabilities in the credential must be a subset of capabilities declared for the agent in the discovery document:

```python
declared_capabilities = set(agent["capabilities"])
claimed_capabilities = set(payload["capabilities"])

if not claimed_capabilities.issubset(declared_capabilities):
    raise VerificationError("capability_mismatch")
```

Wildcard capabilities (`read:*`) in the discovery document match any specific capability (`read:data`, `read:logs`).

### Step 11: Delegation Chain Verification

If the credential includes a delegation chain, the verifier walks the chain to confirm both software provenance (Maker) and operational authorization (Deployer):

1. Fetch the Maker's discovery document
2. Verify the Maker's attestation signature
3. Confirm capabilities narrow (never widen) at each delegation level
4. Check delegation depth doesn't exceed `max_delegation_depth`

```javascript
for (const link of delegationChain) {
    const makerDiscovery = await fetchDiscovery(link.domain);
    const makerKey = findKey(makerDiscovery, link.kid);

    if (!verifySignature(makerKey, link.attestation, link.payload)) {
        return { valid: false, error_code: 'delegation_invalid' };
    }

    // Capabilities must narrow at each level
    if (!isSubset(link.capabilities, parentCapabilities)) {
        return { valid: false, error_code: 'delegation_invalid' };
    }
}
```

### Step 12: TOFU Key Pinning

Trust-On-First-Use: The first time a key is seen for a domain, it is pinned. Subsequent verifications check that the same key is used.

```python
from agentpin import KeyPinStore, PinningResult

pin_store = KeyPinStore()

result = pin_store.check_and_pin(issuer_domain, public_key_jwk)

if result == PinningResult.FIRST_USE:
    # First time seeing this domain — key is now pinned
    pass
elif result == PinningResult.MATCHED:
    # Key matches previously pinned key
    pass
elif result == PinningResult.CHANGED:
    # KEY CHANGED — possible attack
    raise VerificationError("key_changed")
```

---

## Verification Result

The verification result includes:

```json
{
  "valid": true,
  "agent_id": "urn:agentpin:example.com:my-agent",
  "issuer": "example.com",
  "capabilities": ["read:data", "write:reports"],
  "constraints": {},
  "key_pinning": "first_use",
  "delegation_chain_valid": true,
  "error_code": null,
  "error_message": null,
  "verified_at": "2026-02-15T12:00:00Z"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | Overall verification result |
| `agent_id` | string | Verified agent identifier (URN) |
| `issuer` | string | Verified issuer domain |
| `capabilities` | array | Validated capabilities |
| `constraints` | object | Applied constraints |
| `key_pinning` | string | `first_use`, `matched`, or `changed` |
| `delegation_chain_valid` | boolean | Whether delegation chain verified |
| `error_code` | string | Error code if `valid` is false |
| `error_message` | string | Human-readable error description |

---

## Configuration Options

Both JavaScript and Python verifiers accept a configuration object:

### JavaScript

```javascript
const config = {
    clockSkewSecs: 60,     // allowed clock skew (default: 60)
    maxTtlSecs: 86400,     // maximum credential TTL (default: 86400)
};

const result = verifyCredentialOffline(jwt, discovery, null, pinStore, audience, config);
```

### Python

```python
from agentpin import VerifierConfig

config = VerifierConfig(
    clock_skew_secs=60,
    max_ttl_secs=86400,
)

result = verify_credential_offline(jwt, discovery, None, pin_store, audience, config)
```

---

## Error Handling

All verification errors include an `error_code` and `error_message`:

| Error Code | Meaning | Action |
|-----------|---------|--------|
| `invalid_format` | JWT is malformed | Check credential encoding |
| `invalid_algorithm` | Not ES256 | Only ES256 credentials are accepted |
| `expired` | Credential has expired | Issue a new credential |
| `not_yet_valid` | `iat` is in the future | Check clock synchronization |
| `discovery_failed` | Cannot resolve discovery document | Check domain and network |
| `invalid_signature` | Signature verification failed | Credential may be tampered |
| `domain_mismatch` | Issuer doesn't match discovery entity | Possible impersonation |
| `key_not_found` | `kid` not in discovery document | Key may have been rotated |
| `agent_inactive` | Agent not active in discovery | Agent may be suspended |
| `revoked` | Credential, agent, or key is revoked | Do not trust this credential |
| `capability_mismatch` | Capabilities exceed declared scope | Possible capability inflation |
| `delegation_invalid` | Delegation chain verification failed | Check chain integrity |
| `key_changed` | TOFU pin violation | Possible key substitution attack |
