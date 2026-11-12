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
- **`AllowedDomains` typed wrapper** (v0.3.0; tri-state since v0.4) — `null` = unrestricted, `[]` = restricted to nothing, pattern-aware intersection for cross-protocol scoping.
- **Web Bot Auth** (v0.4) — RFC 9421 HTTP message signatures in the Web Bot Auth profile (Ed25519 and RSASSA-PSS SHA-512), signed key directories with SSRF-limited fetching, and an optional binding of a WBA signature to an AgentPin credential (spec §18).
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

// Bound to a Web Bot Auth key: carries cnf.jkt = the key's JWK thumbprint (v0.4)
issueBoundCredential(privateKeyPem, kid, issuer, agentId, audience, capabilities, constraints, delegationChain, ttlSecs, wbaJkt)
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
const scope    = AllowedDomains.intersect(caller, provider);  // null ∩ X = X; disjoint lists -> [] (allows nothing)
```

### Web Bot Auth (v0.4)

Agents sign HTTP requests with their own Ed25519 (or 2048 to 8192-bit RSA)
key and name the HTTPS key directory that publishes it in `Signature-Agent`.
The ES256 credential keys are never used for this.

```javascript
import { wba, httpsig, CachingDirectoryResolver, InMemoryNonceStore } from 'agentpin';

// Agent: create a key and publish its directory at
// https://example.com/.well-known/http-message-signatures-directory
const key = wba.generateSigningKey();               // or wba.loadSigningKey(pem)
const body = wba.directoryToJson(wba.directoryFromKeys([key.publicKey()]));
const headers = wba.signDirectoryResponse(body, 'example.com', [key], Math.floor(Date.now() / 1000), 86400);
// serve `body` as application/http-message-signatures-directory+json with `headers`

// Agent: sign a request (covers @authority, the Signature-Agent member, @method, @path)
const req = httpsig.httpRequest('GET', 'https://shop.example/products');
const signed = wba.signRequest(req, key, wba.wellKnownDirectory('example.com')).apply(req);
// signed.headers now carries Signature-Agent, Signature-Input and Signature

// Origin: verify; directories are fetched over https only, without redirects,
// never from non-public addresses, with size/key/time caps and caching
const keys = new CachingDirectoryResolver();
const result = await wba.verifyRequest(signed, keys, { nonceStore: new InMemoryNonceStore() });
// result.outcome: 'verified' (result.agent), 'invalid' or 'unverified' (result.reason)
```

To attribute a request to an AgentPin identity, issue the credential with
`issueBoundCredential(..., wba.thumbprint(key.publicKey()))`, send it as
`Authorization: AgentPin <jwt>`, and cover it in the signature
(`components: ['@method', '@path', 'authorization']`). The origin then calls
`wba.verifyBoundRequest(req, keys, resolver, pinStore, audience)`, which also
requires `cnf.jkt` to match the signature's keyid and the issuer's discovery
document to vouch for the `Signature-Agent` URL (`web_bot_auth.signature_agents`,
or the issuer's well-known directory when absent).

See [docs/web-bot-auth.md](https://github.com/ThirdKeyAI/AgentPin/blob/main/docs/web-bot-auth.md) for the full guide.

## Cross-Language Interoperability

Credentials and signed A2A AgentCards issued by the JavaScript package verify byte-identically in the [Rust](https://crates.io/crates/agentpin), [Python](https://pypi.org/project/agentpin/), and [Go](https://pkg.go.dev/github.com/ThirdKeyAi/agentpin/go) implementations, and vice versa. All four SDKs use DER-encoded ECDSA signatures, identical JSON field names, and sorted-key canonical JSON for AgentCard signing inputs. Web Bot Auth signing and verification run the shared vectors in `testdata/web_bot_auth/vectors.json`.

## License

MIT — [ThirdKey.ai](https://thirdkey.ai)
