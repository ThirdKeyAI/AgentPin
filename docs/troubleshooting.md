# Troubleshooting

Common issues and solutions when working with AgentPin.

---

## Verification Errors

### `invalid_algorithm`

**Problem:** The JWT header contains an algorithm other than ES256.

```json
{ "valid": false, "error_code": "invalid_algorithm" }
```

**Cause:** The credential was signed with RSA, HS256, EdDSA, or another algorithm.

**Solution:** AgentPin only accepts ES256 (ECDSA P-256). Re-issue the credential using an ES256 key pair:

```javascript
// Ensure you're using an ES256 key pair
const { privateKeyPem, publicKeyPem } = generateKeyPair(); // Always ES256
```

---

### `expired`

**Problem:** The credential's `exp` claim is in the past.

```json
{ "valid": false, "error_code": "expired" }
```

**Solution:** Issue a new credential. Use the `clockSkewSecs` config to allow small time differences:

```javascript
const result = verifyCredentialOffline(jwt, discovery, null, pinStore, audience, {
    clockSkewSecs: 60,  // Allow 60 seconds of clock skew
});
```

---

### `not_yet_valid`

**Problem:** The credential's `iat` (issued-at) timestamp is in the future.

**Cause:** Clock skew between issuer and verifier.

**Solution:** Synchronize clocks with NTP, or increase `clockSkewSecs`:

```python
from agentpin import VerifierConfig

config = VerifierConfig(clock_skew_secs=120)  # Allow 2 minutes of skew
```

---

### `discovery_failed`

**Problem:** Cannot fetch or parse the discovery document.

**Common causes:**

1. **Domain unreachable** — Check DNS and network connectivity
2. **No HTTPS** — Discovery documents must be served over HTTPS
3. **Invalid JSON** — Discovery document is malformed
4. **Redirect** — AgentPin rejects HTTP redirects

**Debug steps:**

```bash
# Check if the endpoint is reachable
curl -sv https://example.com/.well-known/agent-identity.json

# Check for redirects (should NOT redirect)
curl -sI https://example.com/.well-known/agent-identity.json | grep -i location

# Validate JSON
curl -s https://example.com/.well-known/agent-identity.json | jq .
```

---

### `invalid_signature`

**Problem:** The ECDSA signature does not match.

**Common causes:**

1. **Wrong key** — The `kid` in the JWT references a different key than what signed it
2. **Tampered credential** — The JWT was modified after signing
3. **Encoding issue** — Signature encoding mismatch (expect DER-encoded)

**Debug steps:**

```bash
# Decode the JWT header to check the kid
echo "<jwt>" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
# Should show: { "alg": "ES256", "typ": "JWT", "kid": "..." }

# Verify the kid exists in the discovery document
curl -s https://example.com/.well-known/agent-identity.json | jq '.public_keys[].kid'
```

---

### `key_not_found`

**Problem:** The `kid` from the JWT header is not in the discovery document.

**Cause:** Key was rotated or removed from the discovery document.

**Solution:** Check if the key was rotated. If so, re-issue the credential with the current key:

```bash
# List keys in the discovery document
curl -s https://example.com/.well-known/agent-identity.json | jq '.public_keys[] | {kid, exp}'
```

---

### `agent_inactive`

**Problem:** The agent is declared in the discovery document but its status is not `active`.

**Possible statuses:**

| Status | Meaning |
|--------|---------|
| `active` | Agent is operational (verification succeeds) |
| `suspended` | Agent is temporarily disabled (verification fails) |
| `deprecated` | Agent is being retired (verification fails) |

**Solution:** Check with the agent's operator about the status change.

---

### `revoked`

**Problem:** The credential, agent, or key has been revoked.

**Debug steps:**

```bash
# Check revocation document
curl -s https://example.com/.well-known/agent-identity-revocations.json | jq .

# Check specific revocation types
curl -s https://example.com/.well-known/agent-identity-revocations.json | jq '.revoked_credentials'
curl -s https://example.com/.well-known/agent-identity-revocations.json | jq '.revoked_agents'
curl -s https://example.com/.well-known/agent-identity-revocations.json | jq '.revoked_keys'
```

---

### `capability_mismatch`

**Problem:** The credential claims capabilities not declared in the discovery document.

**Debug steps:**

```python
# Decode the JWT payload to see claimed capabilities
import base64, json
payload = jwt.split('.')[1]
payload += '=' * (4 - len(payload) % 4)  # pad base64
claims = json.loads(base64.urlsafe_b64decode(payload))
print("Claimed:", claims.get("capabilities"))

# Compare with discovery document
print("Declared:", discovery["agents"][0]["capabilities"])
```

**Solution:** Re-issue the credential with capabilities that are a subset of the declared capabilities.

---

### `key_changed` (TOFU Pin Violation)

**Problem:** The public key for a domain changed since it was first pinned.

**This is a security event.** Possible causes:

1. **Legitimate key rotation** — The domain rotated keys
2. **Key substitution attack** — An attacker is serving a different key

**Investigation steps:**

1. Confirm the key change with the domain operator out-of-band
2. If legitimate, update the pin store:

```python
pin_store = KeyPinStore.from_json(open("pins.json").read())
pin_store.add_key("example.com", new_jwk)  # Explicitly trust new key
```

3. If suspicious, do not accept the new key and investigate

---

## Cross-Language Issues

### Credential Issued by Python, Verified by JavaScript

If you get `invalid_signature` when cross-verifying, check:

1. Both implementations use DER-encoded signatures (not raw R+S)
2. The JWT encoding is identical (Base64url without padding)

```javascript
// JavaScript verification of Python-issued credential
const result = verifyCredentialOffline(pythonJwt, discovery, null, new KeyPinStore(), audience);
// This should work — all implementations use the same encoding
```

### Key Format Conversion

Convert between PEM and JWK formats:

```javascript
// PEM to JWK
const jwk = pemToJwk(publicKeyPem, 'my-key-id');

// JWK to PEM
const pem = jwkToPem(jwk);
```

```python
# PEM to JWK
jwk = pem_to_jwk(public_key_pem, "my-key-id")

# JWK to PEM
pem = jwk_to_pem(jwk)
```

---

## Trust Bundle Issues

### Bundle Doesn't Contain Expected Domain

```python
from agentpin import find_bundle_discovery

discovery = find_bundle_discovery(bundle, "example.com")
if discovery is None:
    print("Domain not found in bundle")
    # Check what domains are in the bundle:
    for doc in bundle["documents"]:
        print(f"  - {doc['entity']}")
```

### Stale Bundle

Trust bundles are snapshots in time. If keys or agents have changed since the bundle was created, verification may fail:

```bash
# Check bundle freshness
cat trust-bundle.json | jq '.created_at'
cat trust-bundle.json | jq '.documents[].updated_at'

# Rebuild the bundle with fresh data
./rotate-bundle.sh
```

---

## Network Issues

### Redirect Rejection

If your domain redirects `/.well-known/` paths (e.g., HTTP to HTTPS, or www to non-www), online verification will fail.

**Solution:** Ensure the discovery document is served directly at the canonical URL without redirects:

```bash
# This should NOT redirect
curl -sI https://example.com/.well-known/agent-identity.json | head -1
# Expected: HTTP/2 200

# If it redirects, fix your web server configuration
```

### CORS for Browser-Based Verification

If verifying in a browser context, the discovery endpoint needs CORS headers:

```nginx
location /.well-known/agent-identity.json {
    add_header Access-Control-Allow-Origin "*";
    add_header Access-Control-Allow-Methods "GET";
}
```

---

## Getting Help

- **Technical Specification:** [AGENTPIN_TECHNICAL_SPECIFICATION.md](../AGENTPIN_TECHNICAL_SPECIFICATION.md)
- **GitHub Issues:** [github.com/ThirdKeyAI/agentpin/issues](https://github.com/ThirdKeyAI/agentpin/issues)
- **Website:** [agentpin.org](https://agentpin.org)
