# Delegation Chains

AgentPin supports a two-layer trust model where **Makers** (who build agent software) and **Deployers** (who operate agent instances) are independently verifiable through cryptographic delegation chains.

---

## The Maker-Deployer Model

```
┌─────────────────────────────┐     ┌─────────────────────────────┐
│ Maker (anthropic.com)       │     │ Deployer (tarnover.com)     │
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
  "entity": "anthropic.com",
  "entity_type": "maker",
  "public_keys": [
    {
      "kid": "anthropic-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "sig"
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:anthropic.com:claude-agent-v4",
      "name": "Claude Agent Runtime v4",
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
      "agent_type": "urn:agentpin:anthropic.com:claude-agent-v4",
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
            domain: 'anthropic.com',
            kid: 'anthropic-2026-01',
            agent_type: 'urn:agentpin:anthropic.com:claude-agent-v4',
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
import { verifyCredentialOffline, KeyPinStore } from 'agentpin';

// The verifier receives a credential from tarnover.com's agent
// The credential includes a delegation chain pointing back to anthropic.com

const result = verifyCredentialOffline(
    credential,
    deployerDiscovery,    // tarnover.com's discovery document
    null,                 // revocation
    new KeyPinStore(),
    'client-corp.com',    // expected audience
);

// result includes delegation chain validation
if (result.valid && result.delegation_chain_valid) {
    console.log('Agent verified with valid delegation chain');
    console.log('Issuer:', result.issuer);           // tarnover.com
    console.log('Agent:', result.agent_id);           // urn:agentpin:tarnover.com:scout-v2
    console.log('Capabilities:', result.capabilities); // ['read:public-api', 'write:report']
}
```

### Python

```python
from agentpin import verify_credential_offline, KeyPinStore

result = verify_credential_offline(
    credential_jwt=credential,
    discovery=deployer_discovery,
    revocation=None,
    pin_store=KeyPinStore(),
    audience="client-corp.com",
)

if result.valid and result.delegation_chain_valid:
    print(f"Verified with delegation chain")
    print(f"Issuer: {result.issuer}")
    print(f"Agent: {result.agent_id}")
```

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
        "agent_type": "urn:agentpin:anthropic.com:claude-agent-v4",
        "capabilities": ["read:public-api", "read:codebase", "write:report"],
    },
)
# Returns a Base64url-encoded signature
```

### Verifying a Maker Attestation

During delegation chain verification, the verifier:

1. Fetches the Maker's discovery document
2. Finds the public key matching the delegation chain's `kid`
3. Verifies the attestation signature over the Deployer's agent declaration

```python
from agentpin.crypto import verify_es256

# Reconstruct the canonical agent declaration
canonical = canonicalize(deployer_agent_declaration)

# Verify the Maker's signature
valid = verify_es256(maker_public_key, canonical, attestation_bytes)
```

---

## Real-World Example

### Scenario: Security Scanning Service

1. **Anthropic** (Maker) publishes Claude Agent Runtime with broad capabilities
2. **Tarnover** (Deployer) deploys a security scanning instance with narrowed capabilities
3. **Client Corp** (Verifier) receives a credential and verifies the full chain

```
anthropic.com (Maker)
├── Agent type: claude-agent-v4
├── Capabilities: read:*, write:text, execute:code, delegate:agent
└── Attestation: "I authorize tarnover.com to deploy scout-v2"

    tarnover.com (Deployer)
    ├── Agent instance: scout-v2
    ├── Type: claude-agent-v4 (from anthropic.com)
    ├── Capabilities: read:public-api, read:codebase, write:report
    └── Constraints: allowed_domains=*.client-corp.com, rate_limit=100/hour

        Credential (issued by tarnover.com)
        ├── Agent: urn:agentpin:tarnover.com:scout-v2
        ├── Capabilities: read:public-api, write:report
        ├── Audience: client-corp.com
        └── Delegation chain → anthropic.com
```

The verifier at client-corp.com can confirm:
- The agent software was built by Anthropic (trusted Maker)
- The instance is operated by Tarnover (authorized Deployer)
- The capabilities are properly scoped
- The Maker explicitly authorized this deployment
