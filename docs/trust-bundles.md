# Trust Bundles

Trust bundles package discovery and revocation documents together for offline, air-gapped, or enterprise verification environments. Instead of fetching documents over HTTPS at verification time, the verifier uses a pre-loaded bundle.

---

## When to Use Trust Bundles

- **Air-gapped networks** — Environments without internet access
- **CI/CD pipelines** — Deterministic verification without HTTP calls
- **Enterprise deployments** — Centralized trust management
- **Embedded systems** — Pre-provisioned trust data
- **High-throughput verification** — Avoid network latency per verification

---

## Bundle Format

A trust bundle is a JSON object containing arrays of discovery and revocation documents:

```json
{
  "agentpin_version": "0.1",
  "bundle_id": "enterprise-bundle-2026-02",
  "created_at": "2026-02-15T00:00:00Z",
  "documents": [
    {
      "agentpin_version": "0.1",
      "entity": "example.com",
      "entity_type": "maker",
      "public_keys": [ ... ],
      "agents": [ ... ],
      "max_delegation_depth": 2,
      "updated_at": "2026-02-01T00:00:00Z"
    },
    {
      "agentpin_version": "0.1",
      "entity": "partner.com",
      "entity_type": "deployer",
      "public_keys": [ ... ],
      "agents": [ ... ],
      "max_delegation_depth": 1,
      "updated_at": "2026-02-10T00:00:00Z"
    }
  ],
  "revocations": [
    {
      "entity": "example.com",
      "revoked_credentials": [],
      "revoked_agents": [],
      "revoked_keys": []
    }
  ]
}
```

---

## Creating Trust Bundles

### JavaScript

```javascript
import {
    createTrustBundle,
    verifyCredentialWithBundle,
    KeyPinStore,
} from 'agentpin';

// Create an empty bundle
const bundle = createTrustBundle();

// Add discovery documents
bundle.documents.push(makerDiscovery);
bundle.documents.push(deployerDiscovery);

// Add revocation documents
bundle.revocations.push(makerRevocation);
bundle.revocations.push(deployerRevocation);

// Verify a credential using the bundle (no HTTP calls)
const result = verifyCredentialWithBundle(
    credential,
    bundle,
    new KeyPinStore(),
    'verifier.com',
);

if (result.valid) {
    console.log('Verified via trust bundle:', result.agent_id);
}
```

### Python

```python
from agentpin import (
    create_trust_bundle,
    verify_credential_with_bundle,
    save_trust_bundle,
    load_trust_bundle,
    KeyPinStore,
)

# Create an empty bundle
bundle = create_trust_bundle()

# Add discovery and revocation documents
bundle["documents"].append(maker_discovery)
bundle["documents"].append(deployer_discovery)
bundle["revocations"].append(maker_revocation)

# Verify a credential using the bundle
result = verify_credential_with_bundle(
    credential,
    bundle,
    pin_store=KeyPinStore(),
    audience="verifier.com",
)

if result.valid:
    print(f"Verified via trust bundle: {result.agent_id}")
```

### CLI

```bash
# Create a bundle from local documents
agentpin bundle create \
  --discovery ./maker-discovery.json \
  --discovery ./deployer-discovery.json \
  --revocation ./maker-revocations.json \
  --output ./trust-bundle.json

# Verify using a bundle
agentpin verify \
  --credential <jwt> \
  --bundle ./trust-bundle.json \
  --pin-store ./pins.json
```

---

## Saving and Loading Bundles

### Python

```python
from agentpin import save_trust_bundle, load_trust_bundle

# Save bundle to disk
save_trust_bundle(bundle, "trust-bundle.json")

# Load bundle from disk
bundle = load_trust_bundle("trust-bundle.json")
```

### JavaScript

```javascript
import { saveTrustBundle, loadTrustBundle } from 'agentpin';
import fs from 'fs';

// Save to JSON file
fs.writeFileSync('trust-bundle.json', JSON.stringify(bundle, null, 2));

// Load from JSON file
const bundle = JSON.parse(fs.readFileSync('trust-bundle.json', 'utf-8'));
```

---

## Looking Up Documents in a Bundle

The `findBundleDiscovery` function searches the bundle for a discovery document matching a given domain:

### JavaScript

```javascript
import { findBundleDiscovery } from 'agentpin';

const discovery = findBundleDiscovery(bundle, 'example.com');
if (discovery) {
    console.log('Found discovery for:', discovery.entity);
    console.log('Keys:', discovery.public_keys.length);
    console.log('Agents:', discovery.agents.length);
}
```

### Python

```python
from agentpin import find_bundle_discovery

discovery = find_bundle_discovery(bundle, "example.com")
if discovery:
    print(f"Found discovery for: {discovery['entity']}")
```

---

## Enterprise Use Cases

### Centralized Trust Management

In enterprise environments, a security team maintains the trust bundle and distributes it to all agent instances:

```
┌─────────────────────┐
│   Security Team     │
│                     │
│ 1. Collect discovery│
│    documents from   │
│    trusted domains  │
│                     │
│ 2. Build bundle     │
│                     │
│ 3. Distribute via   │
│    config management│
└────────┬────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────┐
│Agent A │ │Agent B │
│        │ │        │
│ Verify │ │ Verify │
│ with   │ │ with   │
│ bundle │ │ bundle │
└────────┘ └────────┘
```

### CI/CD Pipeline Integration

Pin the trust bundle in your repository for deterministic builds:

```yaml
# .github/workflows/verify.yml
steps:
  - name: Verify agent credentials
    run: |
      agentpin verify \
        --credential "$AGENT_CREDENTIAL" \
        --bundle ./trust/bundle.json \
        --pin-store ./trust/pins.json
```

### Bundle Rotation

Update trust bundles periodically to pick up key rotations and new agent declarations:

```bash
#!/bin/bash
# rotate-bundle.sh — Fetch fresh documents and rebuild the bundle

# Fetch latest discovery documents
curl -s https://maker.com/.well-known/agent-identity.json > /tmp/maker.json
curl -s https://deployer.com/.well-known/agent-identity.json > /tmp/deployer.json
curl -s https://maker.com/.well-known/agent-identity-revocations.json > /tmp/maker-rev.json

# Build fresh bundle
agentpin bundle create \
  --discovery /tmp/maker.json \
  --discovery /tmp/deployer.json \
  --revocation /tmp/maker-rev.json \
  --output ./trust-bundle.json

echo "Bundle updated at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

---

## Combining with TOFU Pinning

Trust bundles work seamlessly with TOFU key pinning. The pin store tracks which keys have been seen, regardless of whether they were discovered online or via a bundle:

```python
from agentpin import KeyPinStore, verify_credential_with_bundle

# Persistent pin store
pin_store = KeyPinStore.from_json(open("pins.json").read())

result = verify_credential_with_bundle(
    credential, bundle, pin_store=pin_store, audience="verifier.com"
)

# Save updated pins
with open("pins.json", "w") as f:
    f.write(pin_store.to_json())
```

The first verification for a domain pins the key. Subsequent verifications (even with a different bundle version) will detect key changes.
