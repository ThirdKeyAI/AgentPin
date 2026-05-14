# agentpin

Domain-anchored cryptographic identity for AI agents. Part of the [ThirdKey](https://thirdkey.ai) trust stack ([SchemaPin](https://schemapin.org) → **[AgentPin](https://agentpin.org)** → [Symbiont](https://symbiont.dev)).

Zero external dependencies — uses Node.js built-in `crypto`. Requires Node.js >= 18.

## Install

```bash
npm install agentpin
```

## Quick Start

```javascript
import {
    generateKeyPair,
    generateKeyId,
    pemToJwk,
    issueCredential,
    verifyCredentialOffline,
    buildDiscoveryDocument,
    KeyPinStore,
    Capability,
} from 'agentpin';

// Generate keys
const { privateKeyPem, publicKeyPem } = generateKeyPair();
const kid = generateKeyId(publicKeyPem);
const jwk = pemToJwk(publicKeyPem, kid);

// Build discovery document
const discovery = buildDiscoveryDocument(
    'example.com', 'maker', [jwk],
    [{
        agent_id: 'urn:agentpin:example.com:my-agent',
        name: 'My Agent',
        capabilities: ['read:data', 'write:reports'],
        status: 'active',
    }],
    2, new Date().toISOString()
);

// Issue credential
const credential = issueCredential(
    privateKeyPem, kid, 'example.com',
    'urn:agentpin:example.com:my-agent', 'verifier.com',
    [new Capability('read:data'), new Capability('write:reports')],
    null, null, 3600
);

// Verify credential
const result = verifyCredentialOffline(
    credential, discovery, null, new KeyPinStore(), 'verifier.com',
    { clockSkewSecs: 60, maxTtlSecs: 86400 }
);

if (result.valid) {
    console.log('Agent:', result.agent_id);
    console.log('Capabilities:', result.capabilities);
    console.log('Key pinning:', result.key_pinning);
} else {
    console.error('Failed:', result.error_code, result.error_message);
}
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
- **Zero dependencies** — Node.js built-in crypto only

## API

### Key Management

```javascript
generateKeyPair()              // → { privateKeyPem, publicKeyPem }
generateKeyId(publicKeyPem)    // → kid (hex SHA-256)
pemToJwk(publicKeyPem, kid)    // → JWK object
jwkToPem(jwk)                  // → PEM string
```

### Credentials

```javascript
issueCredential(privateKeyPem, kid, issuer, agentId, audience, capabilities, constraints, delegationChain, ttlSecs)
// → compact JWT string
```

### Verification

```javascript
// Offline (with local discovery document)
verifyCredentialOffline(jwt, discovery, revocation, pinStore, audience, config)
// → { valid, agent_id, issuer, capabilities, key_pinning, error_code, ... }

// Online (auto-fetches discovery from issuer domain)
await verifyCredential(jwt, pinStore, audience, config)
```

### Discovery & Revocation

```javascript
buildDiscoveryDocument(entity, entityType, publicKeys, agents, maxDelegationDepth, updatedAt)
buildRevocationDocument(entity)
addRevokedCredential(doc, jti, reason)
addRevokedAgent(doc, agentId, reason)
addRevokedKey(doc, kid, reason)
```

### Mutual Authentication

```javascript
import { createChallenge, createResponse, verifyResponse } from 'agentpin/mutual';

const challenge = createChallenge(verifierCredential);
const response = createResponse(challenge, privateKeyPem, kid);
verifyResponse(response, challenge.nonce, publicKeyPem);
```

### Trust Bundles (v0.2.0)

```javascript
import {
    createTrustBundle,
    findBundleDiscovery,
    verifyCredentialWithBundle,
} from 'agentpin';

// Create a bundle with pre-loaded discovery documents
const bundle = createTrustBundle();
bundle.documents.push(discovery);
bundle.revocations.push(revocation);

// Verify without any HTTP calls
const result = verifyCredentialWithBundle(
    credential, bundle, pinStore, 'verifier.com'
);
```

### Key Pinning

```javascript
import { KeyPinStore } from 'agentpin/pinning';

const store = new KeyPinStore();
const result = store.checkAndPin(domain, jwk); // 'first_use' | 'matched' | 'changed'
store.addKey(domain, jwk);                      // allow key rotation
const json = store.toJson();                    // persist
const restored = KeyPinStore.fromJson(json);    // restore
```

### A2A AgentCards (v0.3.0)

```javascript
import {
    buildAndSignAgentCard,
    verifyAgentpinExtension,
    LocalAgentCardStore,
    A2aAgentCardResolver,
} from 'agentpin';

// Build + sign an A2A AgentCard from an AgentPin declaration
const card = buildAndSignAgentCard(
    'https://example.com/agent',
    declaration,
    privateKeyPem,
    'example-2026-05',
    'https://example.com/.well-known/agent-identity.json',
    { streaming: true },
);

// Verify (extension signature only — pair with discovery for full chain)
verifyAgentpinExtension(card);

// Push-based: register a card inline (no HTTP)
const store = new LocalAgentCardStore();
store.register(card);                                    // verifies signature
const doc = store.resolveDiscovery('example.com');       // -> derived DiscoveryDocument

// Pull-based: fetch + verify over HTTPS
const resolver = new A2aAgentCardResolver();
const fetched = await resolver.resolveDiscovery('example.com');
```

See [docs/a2a-agentcards.md](https://github.com/ThirdKeyAI/AgentPin/blob/main/docs/a2a-agentcards.md) for the full guide.

### DNS TXT cross-verification (v0.3.0)

```javascript
import { parseTxtRecord, verifyDnsMatch, fetchDnsTxt } from 'agentpin';

// Parse a TXT value retrieved out-of-band
const record = parseTxtRecord('v=agentpin1; kid=example-2026-05; fp=sha256:abcd...');
verifyDnsMatch(discoveryDoc, record);            // throws DISCOVERY_INVALID on mismatch

// Or look it up live via Node's built-in dns/promises
const fetched = await fetchDnsTxt('example.com'); // null when no record exists
```

### AllowedDomains (v0.3.0)

```javascript
import { AllowedDomains } from 'agentpin';

const caller   = AllowedDomains.fromConstraints(callerCredential.constraints);
const provider = AllowedDomains.fromConstraints(providerAgent.constraints);
const scope    = AllowedDomains.intersect(caller, provider);  // unrestricted ∩ X = X
```

## Cross-Language Interoperability

Credentials and signed A2A AgentCards issued by the JavaScript package verify byte-identically in the [Rust](https://crates.io/crates/agentpin), [Python](https://pypi.org/project/agentpin/), and [Go](https://pkg.go.dev/github.com/ThirdKeyAi/agentpin/go) implementations, and vice versa. All four SDKs use DER-encoded ECDSA signatures, identical JSON field names, and sorted-key canonical JSON for AgentCard signing inputs.

## License

MIT — [ThirdKey.ai](https://thirdkey.ai)
