# Delegation Chains

AgentPin supports a two-layer trust model where **Makers** (who build agent software) and **Deployers** (who operate agent instances) are independently verifiable through cryptographic delegation chains.

---

## The Maker-Deployer Model

```
┌─────────────────────────────┐     ┌─────────────────────────────┐
│ Maker (maker-corp.com)      │     │ Deployer (tarnover.com)     │
│                             │     │                             │
│ "We built this agent type"  │────>│ "We run an instance of it"  │
│                             │     │                             │
│ Discovery: agent types,     │     │ Discovery: agent instances,  │
│ baseline capabilities       │     │ scoped capabilities          │
└─────────────────────────────┘     └─────────────────────────────┘
```

- **Maker** — Creates agent software. Publishes agent *types* with baseline capabilities.
- **Deployer** — Operates agent instances. Publishes agent *instances* with scoped capabilities that must be a subset of the Maker's baseline.

---

## How Delegation Works

### 1. Maker Publishes Agent Type

The Maker publishes a discovery document declaring agent types and their maximum capabilities:

```json
{
  "agentpin_version": "0.1",
  "entity": "maker-corp.com",
  "entity_type": "maker",
  "public_keys": [
    {
      "kid": "maker-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "sig"
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:maker-corp.com:assistant-agent-v4",
      "name": "Assistant Agent Runtime v4",
      "capabilities": ["read:*", "write:text", "execute:code", "delegate:agent"],
      "status": "active"
    }
  ],
  "max_delegation_depth": 2,
  "updated_at": "2026-01-15T00:00:00Z"
}
```

### 2. Deployer Creates Agent Instance

The Deployer's discovery document references the Maker's agent type and includes a `maker_attestation` — a cryptographic signature from the Maker proving the Maker authorized this deployment:

```json
{
  "agentpin_version": "0.1",
  "entity": "tarnover.com",
  "entity_type": "deployer",
  "public_keys": [
    {
      "kid": "tarnover-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:tarnover.com:scout-v2",
      "agent_type": "urn:agentpin:maker-corp.com:assistant-agent-v4",
      "name": "Scout Security Analyzer",
      "capabilities": ["read:public-api", "read:codebase", "write:report"],
      "constraints": {
        "allowed_domains": ["*.client-corp.com", "tarnover.com"],
        "rate_limit": "100/hour"
      },
      "maker_attestation": "MEUCIQD7y2F8...",
      "status": "active"
    }
  ],
  "max_delegation_depth": 1,
  "updated_at": "2026-02-01T00:00:00Z"
}
```

### 3. Deployer Issues Credentials

The Deployer issues credentials for its agent instance. The credential includes a delegation chain linking back to the Maker:

```javascript
import { issueCredential, Capability } from 'agentpin';

const credential = issueCredential(
    deployerPrivateKey,
    'tarnover-2026-01',
    'tarnover.com',
    'urn:agentpin:tarnover.com:scout-v2',
    'client-corp.com',
    [
        new Capability('read:public-api'),
        new Capability('write:report'),
    ],
    { allowed_domains: ['*.client-corp.com'] },
    [
        {
            domain: 'maker-corp.com',
            kid: 'maker-2026-01',
            agent_type: 'urn:agentpin:maker-corp.com:assistant-agent-v4',
            attestation: makerAttestation,
        },
    ],
    3600,
);
```

---

## Capability Narrowing

A fundamental rule of delegation chains: **capabilities must narrow at each level, never widen**.

```
Maker capabilities:    read:*  write:text  execute:code  delegate:agent
                          ↓        ↓
Deployer capabilities: read:public-api  read:codebase  write:report
                          ↓                              ↓
Credential capabilities: read:public-api               write:report
```

The verifier checks that each level's capabilities are a subset of the parent level:

```python
# Verification pseudocode
maker_caps = {"read:*", "write:text", "execute:code", "delegate:agent"}
deployer_caps = {"read:public-api", "read:codebase", "write:report"}
credential_caps = {"read:public-api", "write:report"}

# Deployer caps must be subset of Maker caps (with wildcard matching)
assert matches_with_wildcards(deployer_caps, maker_caps)

# Credential caps must be subset of Deployer caps
assert credential_caps.issubset(deployer_caps)
```

Wildcard matching: `read:*` in the Maker's capabilities matches `read:public-api`, `read:codebase`, etc. in the Deployer's capabilities.

---

## Delegation Depth

The maximum delegation depth is enforced at each level:

| Depth | Chain |
|-------|-------|
| 0 | Direct — no delegation allowed |
| 1 | Maker → Deployer |
| 2 | Maker → Deployer → Sub-deployer |
| 3 | Maximum (Maker → Deployer → Sub-deployer → Sub-sub-deployer) |

Each entity declares `max_delegation_depth` in its discovery document. The effective maximum is the minimum across the chain:

```javascript
// If Maker allows depth 2 but Deployer allows depth 1,
// the effective maximum depth is 1
const effectiveMaxDepth = Math.min(
    makerDiscovery.max_delegation_depth,
    deployerDiscovery.max_delegation_depth,
);
```

---

## Verifying Delegation Chains

When a credential includes a delegation chain, the verifier walks the chain:

### JavaScript

```javascript
import { verifyCredentialOffline, verifyCredentialWithBundle, KeyPinStore } from 'agentpin';

// The verifier receives a credential from tarnover.com's agent
// The credential includes a delegation chain pointing back to maker-corp.com.
// The verifier needs the Maker's discovery document too: pass a chain
// resolver (any object with a synchronous resolveDiscovery(domain)), or use
// a trust bundle that contains both documents.

const chainResolver = {
    resolveDiscovery(domain) {
        if (domain === 'maker-corp.com') return makerDiscovery;
        throw new Error(`unknown attester ${domain}`);
    },
};

const result = verifyCredentialOffline(
    credential,
    deployerDiscovery,    // tarnover.com's discovery document
    null,                 // revocation
    new KeyPinStore(),
    'client-corp.com',    // expected audience
    undefined,            // config (defaults: requireDelegationVerification = true)
    chainResolver,
);

// With the default config, `valid` is only true when the chain verified
if (result.valid) {
    console.log(result.delegation_verified);           // true
    console.log(result.delegation_chain);              // [{ domain: 'maker-corp.com', role: 'maker', verified: true }]
    console.log('Issuer:', result.issuer);             // tarnover.com
    console.log('Agent:', result.agent_id);            // urn:agentpin:tarnover.com:scout-v2
    console.log('Capabilities:', result.capabilities); // ['read:public-api', 'write:report']
}

// Without a chain resolver the credential is rejected with DELEGATION_INVALID;
// only `{ requireDelegationVerification: false }` accepts it, and then
// result.delegation_verified is false and result.warnings is non-empty.
```

The online verifiers (`verifyCredential`, `verify_credential`, `verify_credential_with_resolver`, `VerifyCredentialWithResolver`) resolve the attesters' documents themselves.

### Python

```python
from agentpin import verify_credential_offline, KeyPinStore


class ChainResolver:
    def resolve_discovery(self, domain):
        if domain == "maker-corp.com":
            return maker_discovery
        raise RuntimeError(f"unknown attester {domain}")


result = verify_credential_offline(
    credential_jwt=credential,
    discovery=deployer_discovery,
    revocation=None,
    pin_store=KeyPinStore(),
    audience="client-corp.com",
    chain_resolver=ChainResolver(),
)

if result.valid:  # only true when the chain verified (require_delegation_verification=True)
    print(result.delegation_verified)   # True
    print(f"Issuer: {result.issuer}")
    print(f"Agent: {result.agent_id}")
```

`verify_credential_with_bundle` passes the bundle itself as the chain resolver, so a bundle that contains both the Deployer's and the Maker's documents verifies the chain offline.

---

## Maker Attestation

The `maker_attestation` field in the Deployer's agent declaration is a Base64url-encoded ECDSA signature from the Maker over the canonical form of the agent declaration. This proves the Maker explicitly authorized this deployment.

### Creating a Maker Attestation

```python
from agentpin import sign_maker_attestation

# The Maker signs the Deployer's agent declaration
attestation = sign_maker_attestation(
    maker_private_key_pem=maker_private_key,
    deployer_agent_declaration={
        "agent_id": "urn:agentpin:tarnover.com:scout-v2",
        "agent_type": "urn:agentpin:maker-corp.com:assistant-agent-v4",
        "capabilities": ["read:public-api", "read:codebase", "write:report"],
    },
)
# Returns an attestation dict whose "attestation" is a standard-base64 DER signature
```

### Verifying a Maker Attestation

During delegation chain verification, the verifier:

1. Resolves the Maker's discovery document (normalized domain)
2. Finds the public key matching the delegation chain's `kid` and checks it is a usable, unexpired signature key
3. Verifies the attestation signature over the domain-separated attestation input (`agentpin-attestation-v1` context; attester domain, role, agent id, delegatee domain and agent id, capabilities hash, attester `kid`, optional `exp`)
4. Checks that the credential's capabilities stay within what the Maker declares for the attested agent, and that the agent is active
5. Bounds the chain depth by the minimum `max_delegation_depth` of every participant

```python
from agentpin import find_key_by_kid, jwk_to_pem, verify_attestation

maker_key = find_key_by_kid(maker_discovery, attestation["kid"])
verify_attestation(
    attestation,
    jwk_to_pem(maker_key),
    "tarnover.com",                              # delegatee domain (the credential's iss)
    "urn:agentpin:tarnover.com:scout-v2",        # delegatee agent id (the credential's sub)
    credential_capabilities,                     # the credential's capabilities
)  # raises AgentPinError(DELEGATION_INVALID) on failure
```

---

## Real-World Example

### Scenario: Security Scanning Service

1. **Maker Corp** (Maker) publishes Assistant Agent Runtime with broad capabilities
2. **Tarnover** (Deployer) deploys a security scanning instance with narrowed capabilities
3. **Client Corp** (Verifier) receives a credential and verifies the full chain

```
maker-corp.com (Maker)
├── Agent type: assistant-agent-v4
├── Capabilities: read:*, write:text, execute:code, delegate:agent
└── Attestation: "I authorize tarnover.com to deploy scout-v2"

    tarnover.com (Deployer)
    ├── Agent instance: scout-v2
    ├── Type: assistant-agent-v4 (from maker-corp.com)
    ├── Capabilities: read:public-api, read:codebase, write:report
    └── Constraints: allowed_domains=*.client-corp.com, rate_limit=100/hour

        Credential (issued by tarnover.com)
        ├── Agent: urn:agentpin:tarnover.com:scout-v2
        ├── Capabilities: read:public-api, write:report
        ├── Audience: client-corp.com
        └── Delegation chain → maker-corp.com
```

The verifier at client-corp.com can confirm:
- The agent software was built by Maker Corp (trusted Maker)
- The instance is operated by Tarnover (authorized Deployer)
- The capabilities are properly scoped
- The Maker explicitly authorized this deployment
