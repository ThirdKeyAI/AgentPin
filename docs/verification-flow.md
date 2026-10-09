# The 12-Step Verification Flow

AgentPin verifies agent credentials through a comprehensive 12-step protocol. This guide explains each step, shows how to implement custom verification logic, and covers error handling.

---

## Overview

When a verifier receives an AgentPin credential (JWT), it performs these steps in order:

| Step | Name | Failure Mode |
|------|------|-------------|
| 1 | JWT Parsing | `ALGORITHM_REJECTED` — malformed structure, wrong `alg` or `typ`; `MALFORMED_CREDENTIAL` — claims missing, mistyped or inconsistent |
| 2 | Algorithm Check | `ALGORITHM_REJECTED` — must be ES256 |
| 3 | Temporal Validation | `CREDENTIAL_EXPIRED` — `exp`, `iat`, `nbf`, max TTL and `credential_ttl_max` |
| 4 | Discovery Resolution | `DISCOVERY_FETCH_FAILED` — cannot fetch/resolve discovery document; `DISCOVERY_INVALID` — malformed document or non-hostname `iss` |
| 5 | Signature Verification | `SIGNATURE_INVALID` — ECDSA signature does not match |
| 6 | Domain Binding | `DOMAIN_MISMATCH` — normalized issuer domain doesn't match discovery entity |
| 7 | Key Matching | `KEY_NOT_FOUND` — `kid` not in discovery document, or key not usable for signatures; `KEY_EXPIRED` |
| 8 | Agent Status | `AGENT_NOT_FOUND` / `AGENT_INACTIVE` |
| 9 | Revocation Checking | `CREDENTIAL_REVOKED` / `AGENT_INACTIVE` / `KEY_REVOKED`; `DISCOVERY_INVALID` for a malformed or foreign revocation document |
| 10 | Capability Validation | `CAPABILITY_EXCEEDED` — claimed capabilities exceed declared, or violate the taxonomy |
| 11 | Delegation Chain | `DELEGATION_INVALID` / `DELEGATION_DEPTH_EXCEEDED` — chain verification failure, including a chain that cannot be verified |
| 12 | TOFU Key Pinning | `KEY_PIN_MISMATCH` — key doesn't match previously pinned key |

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
- `typ` — Type (must be `agentpin-credential+jwt`)
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

Claim shape is validated here: `iss`/`sub`/`jti` must be non-empty strings, `iat`/`exp` non-negative integers with `exp > iat`, `capabilities` an array of strings and `agentpin_version` `"0.1"`. Anything else fails with `MALFORMED_CREDENTIAL` before any cryptography runs. Base64url segments must be strict (no padding, canonical bits).

### Step 2: Algorithm Check

AgentPin mandates ES256 (ECDSA with P-256) exclusively. Any other algorithm is immediately rejected. This prevents algorithm confusion attacks where an attacker substitutes a weaker algorithm.

```javascript
// The verifier checks:
if (header.alg !== 'ES256' || header.typ !== 'agentpin-credential+jwt') {
    return { valid: false, error_code: 'ALGORITHM_REJECTED' };
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

# Check TTL doesn't exceed the verifier's cap ...
ttl = payload["exp"] - payload["iat"]
if ttl > max_ttl_secs:
    raise VerificationError("CREDENTIAL_EXPIRED")

# ... and, once the agent is found (step 8), the agent's own declared cap
if ttl > agent.get("credential_ttl_max", 86400):
    raise VerificationError("CREDENTIAL_EXPIRED")
```

**Best practice:** Use short-lived credentials (hours, not days). The default maximum TTL is 86400 seconds (24 hours), and the agent declaration's `credential_ttl_max` (spec §5.7) is enforced as a second, per-agent cap.

### Step 4: Discovery Resolution

The verifier extracts the `iss` (issuer) claim, normalizes it (lowercase, one trailing dot removed, IDNA A-labels) and rejects anything that is not a bare hostname — a scheme, port, path, userinfo or IP literal fails with `DISCOVERY_INVALID` before any request is sent. It then resolves the discovery document. Resolution can happen via:

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

HTTP redirects are rejected to prevent redirect-based attacks; every fetch has a 10 s timeout, a 1 MiB body cap and requires a JSON content type.

### Step 5: Signature Verification

The verifier resolves the public key using the `kid` from the JWT header, then verifies the ES256 signature over the `header.payload` portion of the JWT.

```python
from agentpin import find_key_by_kid, jwk_to_pem, verify_jwt

# Find the public key matching the kid; it must be a usable signature key
# (use == "sig", key_ops includes "verify" when present, exp not passed)
jwk = find_key_by_kid(discovery, header["kid"])
if jwk is None:
    raise VerificationError("KEY_NOT_FOUND")

# Verify the ECDSA signature over "<header>.<payload>" (DER-encoded signature)
verify_jwt(credential_jwt, jwk_to_pem(jwk))
```

### Step 6: Domain Binding

The normalized `iss` claim in the JWT must match the normalized `entity` field in the discovery document, and the document's `revocation_endpoint` / `a2a_endpoint` (when present) must be `https://` URLs on that same host:

```javascript
if (normalizeDomain(payload.iss) !== normalizeDomain(discovery.entity)) {
    return { valid: false, error_code: 'DOMAIN_MISMATCH' };
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
    raise VerificationError("AGENT_INACTIVE")
```

### Step 9: Revocation Checking

The verifier checks the revocation document (if available) for three revocation types:

```javascript
// The document is validated structurally first: it must belong to the issuer
// (entity), every entry must carry its identifying field, and a signature
// (if present) must verify under a discovery key — otherwise DISCOVERY_INVALID.

// Check credential-level revocation (by jti)
if (revocation.revoked_credentials?.some(r => r.jti === payload.jti)) {
    return { valid: false, error_code: 'CREDENTIAL_REVOKED' };
}

// Check agent-level revocation (by agent_id)
if (revocation.revoked_agents?.some(r => r.agent_id === payload.sub)) {
    return { valid: false, error_code: 'AGENT_INACTIVE' };
}

// Check key-level revocation (by kid)
if (revocation.revoked_keys?.some(r => r.kid === header.kid)) {
    return { valid: false, error_code: 'KEY_REVOKED' };
}
```

### Step 10: Capability Validation

Capabilities in the credential must be a subset of capabilities declared for the agent in the discovery document:

```python
from agentpin import capabilities_subset

if not capabilities_subset(agent["capabilities"], payload["capabilities"]):
    raise VerificationError("CAPABILITY_EXCEEDED")
```

Wildcard capabilities (`read:*`) in the discovery document match any specific capability (`read:data`, `read:logs`). `admin:*` is never accepted, and with `strict_capabilities` (the default) every capability must follow the §10 taxonomy. Constraints are then merged: the credential may only narrow the discovery declaration's constraints, and the result carries the effective (merged) set.

### Step 11: Delegation Chain Verification

If the credential includes a delegation chain, the verifier walks the chain to confirm both software provenance (Maker) and operational authorization (Deployer):

1. Resolve the attester's discovery document (through the same resolver used for the issuer, a dedicated chain resolver, a trust bundle, or pre-fetched over HTTPS)
2. Verify the attestation signature with the attester's key (`kid`) over the domain-separated attestation input, with delegatee = the credential's `iss`/`sub` and the credential's capabilities
3. Confirm capabilities narrow (never widen): the credential's capabilities must be within what the attester declares for the attested agent, which must be active
4. Check delegation depth doesn't exceed the minimum `max_delegation_depth` across all participants

```javascript
for (const link of payload.delegation_chain) {
    const attesterDoc = chainResolver.resolveDiscovery(normalizeDomain(link.domain));
    const key = findKeyByKid(attesterDoc, link.kid);
    verifyAttestation(link, jwkToPem(key), payload.iss, payload.sub, payload.capabilities);
    // Capabilities must narrow at each level
    validateCredentialAgainstDiscovery(payload.capabilities, findAgentById(attesterDoc, link.agent_id).capabilities);
}
verifyChainDepth(payload.delegation_chain.length, [discovery.max_delegation_depth, ...attesterDepths]);
```

A chain that cannot be verified (for example offline with no chain resolver) is rejected with `DELEGATION_INVALID`. Only with `require_delegation_verification` set to false is such a credential accepted, and then the result carries `delegation_verified: false` and a warning.

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
    raise VerificationError("KEY_PIN_MISMATCH")
```

Pins are keyed on the normalized issuer domain, so case variants and trailing dots share one pin set.

---

## Verification Result

The verification result includes:

```json
{
  "valid": true,
  "agent_id": "urn:agentpin:example.com:my-agent",
  "issuer": "example.com",
  "capabilities": ["read:data", "write:reports"],
  "constraints": { "allowed_domains": ["*.client-corp.com"], "rate_limit": "100/hour" },
  "delegation_verified": true,
  "delegation_chain": [ { "domain": "maker.com", "role": "maker", "verified": true } ],
  "key_pinning": { "status": "first_use", "first_seen": "2026-02-15T12:00:00Z" },
  "warnings": []
}
```

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | Overall verification result. `true` only when every present feature verified (strict result) |
| `agent_id` | string | Verified agent identifier (URN) |
| `issuer` | string | Verified issuer domain (normalized) |
| `capabilities` | array | Validated capabilities |
| `constraints` | object | Effective constraints: discovery defaults narrowed by the credential |
| `delegation_verified` | boolean | Whether the delegation chain verified (absent when no chain) |
| `delegation_chain` | array | One `{domain, role, verified}` entry per attestation |
| `key_pinning` | object | `{"status": "first_use" \| "pinned", "first_seen": ...}` |
| `error_code` | string | Error code if `valid` is false |
| `error_message` | string | Human-readable error description |
| `warnings` | array | Non-fatal notes (only non-empty with explicit opt-outs) |

---

## Configuration Options

Both JavaScript and Python verifiers accept a configuration object:

### JavaScript

```javascript
const config = {
    clockSkewSecs: 60,                   // allowed clock skew (default: 60)
    maxTtlSecs: 86400,                   // maximum credential TTL (default: 86400)
    strictCapabilities: true,            // enforce the capability taxonomy (default: true)
    requireDelegationVerification: true, // reject chains that cannot be verified (default: true)
    requireSignedRevocation: false,      // reject unsigned revocation documents (default: false)
    revocationMaxAgeSecs: null,          // reject stale revocation documents when set
};

const result = verifyCredentialOffline(jwt, discovery, null, pinStore, audience, config);
```

### Python

```python
from agentpin import VerifierConfig

config = VerifierConfig(
    clock_skew_secs=60,
    max_ttl_secs=86400,
    strict_capabilities=True,
    require_delegation_verification=True,
    require_signed_revocation=False,
    revocation_max_age_secs=None,
)

result = verify_credential_offline(jwt, discovery, None, pin_store, audience, config)
```

---

## Error Handling

All verification errors include an `error_code` and `error_message`:

| Error Code | Meaning | Action |
|-----------|---------|--------|
| `ALGORITHM_REJECTED` | JWT structure, `alg` or `typ` is wrong | Only ES256 `agentpin-credential+jwt` credentials are accepted |
| `MALFORMED_CREDENTIAL` | Claims missing, mistyped or inconsistent | Check the issuer's claim set |
| `CREDENTIAL_EXPIRED` | Expired, not yet valid, or lifetime over a cap | Issue a new credential |
| `DISCOVERY_FETCH_FAILED` | Cannot resolve discovery or revocation document | Check domain and network |
| `DISCOVERY_INVALID` | Discovery/revocation document failed validation, or `iss` is not a hostname | Fix the published documents |
| `SIGNATURE_INVALID` | Signature verification failed | Credential may be tampered |
| `DOMAIN_MISMATCH` | Issuer doesn't match discovery entity | Possible impersonation |
| `KEY_NOT_FOUND` | `kid` not in discovery document, or key not usable for signatures | Key may have been rotated |
| `KEY_EXPIRED` | Key `exp` passed or unparsable | Rotate the key |
| `AGENT_NOT_FOUND` / `AGENT_INACTIVE` | Agent not declared / not active | Agent may be suspended |
| `CREDENTIAL_REVOKED` / `KEY_REVOKED` | Credential or key is revoked | Do not trust this credential |
| `CAPABILITY_EXCEEDED` | Capabilities exceed declared scope or violate the taxonomy | Possible capability inflation |
| `CONSTRAINT_VIOLATION` | Credential widens a discovery constraint | Narrow the credential's constraints |
| `DELEGATION_INVALID` / `DELEGATION_DEPTH_EXCEEDED` | Delegation chain verification failed or could not be performed | Check chain integrity |
| `AUDIENCE_MISMATCH` | `aud` does not match the verifier | Issue for the right audience |
| `KEY_PIN_MISMATCH` | TOFU pin violation | Possible key substitution attack |
