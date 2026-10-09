# A2A AgentCards

> **New in v0.3.0.** AgentPin extends the [Google A2A](https://github.com/google-a2a/A2A) AgentCard
> format with a cryptographic-identity payload. AgentCards published this way
> can be verified against the AgentPin trust chain (TOFU pinning, revocation,
> capability narrowing) without an extra round-trip to the publisher's
> `agent-identity.json`.

This guide covers when to use A2A AgentCards, how to issue + verify them in each SDK, and how the two new resolvers (`LocalAgentCardStore` and `A2aAgentCardResolver`) compose with the existing AgentPin resolver chain.

For the normative wire format, see [§4.10 of the spec](https://github.com/ThirdKeyAI/AgentPin/blob/main/AGENTPIN_TECHNICAL_SPECIFICATION.md#410-a2a-agentcard-extension-v03).

---

## When to use A2A AgentCards

| Situation | Use AgentCards? |
|-----------|-----------------|
| Your agent already publishes an A2A AgentCard at `/.well-known/agent-card.json`. | Yes — sign it with the AgentPin extension so AgentPin verifiers can use it directly. |
| You operate a coordinator (e.g. Symbiont) that receives agents *inline* at registration time, not by URL. | Yes — use `LocalAgentCardStore`; no HTTP round trip needed. |
| Your agent is reachable only through `agent-identity.json` and your callers are all native AgentPin. | No — stick with `agent-identity.json` discovery. The AgentCard is additive, not a replacement. |
| You need to scope tool verification across a SchemaPin + AgentPin pair. | Yes — the `allowed_domains` field on the AgentCard plus the `AllowedDomains` intersection helper (§4.11) compose with SchemaPin v1.4 `A2aVerificationContext`. |

The AgentCard does not replace `agent-identity.json` — both are part of the AgentPin v0.3 surface, and the AgentCard's signed extension contains a back-pointer to the entity's discovery document for callers that want to walk the full chain.

---

## What the signed extension looks like

A signed AgentCard is an A2A `AgentCard` JSON object with an additional `agentpin` field:

```json
{
  "name": "Tarnover Field Analyst",
  "description": "Reads customer reports, writes invoices",
  "version": "1.0.0",
  "url": "https://tarnover.com/agent",
  "capabilities": {
    "streaming": true,
    "pushNotifications": false,
    "allowed_domains": ["partner-corp.com"]
  },
  "skills": [
    { "id": "read:customers/*", "name": "read:customers/*" },
    { "id": "write:invoices/*", "name": "write:invoices/*" }
  ],
  "agentpin": {
    "agentpin_endpoint": "https://tarnover.com/.well-known/agent-identity.json",
    "public_key_jwk": { "kid": "tarnover-2026-05", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "sig" },
    "signature": "MEUCIQD..."
  }
}
```

The `agentpin.signature` is a detached ECDSA P-256 signature over the canonical bytes of the *rest* of the AgentCard (everything except the `agentpin` field itself). The canonicalisation is sorted-key, compact JSON with `null`/`undefined` fields dropped — byte-identical across all four AgentPin SDKs so a card signed in Rust verifies in JavaScript, Python, and Go without translation.

---

## Issuing a signed AgentCard

The pattern is the same in every SDK: build the card from your existing `AgentDeclaration` (or its equivalent), then call the one-shot `BuildAndSign` helper.

### Rust

```rust
use agentpin::a2a::A2aAgentCardBuilder;

let card = A2aAgentCardBuilder::from_declaration("https://tarnover.com/agent", &agent_declaration)
    .agentpin_endpoint("https://tarnover.com/.well-known/agent-identity.json")
    .streaming(true)
    .sign(&private_key_pem, "tarnover-2026-05")?;
```

### JavaScript

```javascript
import { buildAndSignAgentCard } from 'agentpin';

const card = buildAndSignAgentCard(
    'https://tarnover.com/agent',
    agentDeclaration,
    privateKeyPem,
    'tarnover-2026-05',
    'https://tarnover.com/.well-known/agent-identity.json',
    { streaming: true },
);
```

### Python

```python
from agentpin import build_and_sign_agent_card

card = build_and_sign_agent_card(
    "https://tarnover.com/agent",
    agent_declaration,
    private_key_pem,
    "tarnover-2026-05",
    "https://tarnover.com/.well-known/agent-identity.json",
    streaming=True,
)
```

### Go

```go
import "github.com/ThirdKeyAi/agentpin/go/pkg/a2a"

card, err := a2a.BuildAndSignAgentCard(
    "https://tarnover.com/agent",
    declaration,
    privateKeyPEM,
    "tarnover-2026-05",
    "https://tarnover.com/.well-known/agent-identity.json",
    a2a.BuildOptions{Streaming: true},
)
```

The output is a serialisable AgentCard you can drop straight into your A2A `.well-known/agent-card.json`.

---

## Verifying a signed AgentCard

`verify_agentpin_extension(card)` (Python) / `verifyAgentpinExtension(card)` (JS) / `a2a.VerifyAgentpinExtension(&card)` (Go) / `agentpin::a2a::verify_agentpin_extension(&card)` (Rust) check:

1. The card has an `agentpin` extension whose `agentpin_endpoint` is an `https://` URL with a domain host.
2. The domain-separated canonical bytes of the card — every field including unknown upstream ones, with `agentpin` replaced by `{agentpin_endpoint, public_key_jwk}` and wrapped in the `agentpin-agentcard-v1` context — verify against `agentpin.public_key_jwk` and `agentpin.signature`. Re-pointing `agentpin_endpoint` at another domain therefore breaks the signature.

**Verification of the extension alone is not enough to trust the card.** It only proves the card has not been tampered with relative to the key inside its own extension. The full trust chain requires also confirming that `agentpin.public_key_jwk` is one of the keys in the entity's AgentPin discovery document at `agentpin.agentpin_endpoint` (spec §4.10.4 step 5). The two resolvers below enforce this: `A2aAgentCardResolver` fetches the discovery document and checks the key by thumbprint, and `LocalAgentCardStore` requires a trust anchor at construction.

---

## Resolving an AgentCard

AgentPin v0.3 ships two new resolvers that turn an AgentCard into a usable `DiscoveryDocument`:

### `LocalAgentCardStore` — push-based, in-memory

For coordinators that receive AgentCard JSON *inline* (not by URL) — e.g. Symbiont's external-agent registration flow:

```python
from agentpin import LocalAgentCardStore, extension_key_thumbprint

# Anchor the store on the key thumbprints the operator has verified out of band ...
store = LocalAgentCardStore(trusted_thumbprints=[extension_key_thumbprint(card["agentpin"])])
# ... or on a resolver whose discovery document for the domain must publish the card key:
#     store = LocalAgentCardStore(resolver=bundle_resolver)
# ... or opt out explicitly when the registration channel itself authenticates the registrant:
#     store = LocalAgentCardStore(unanchored=True)

store.register(card)                                # verifies signature + trust anchor, derives discovery
store.register_for_domain(card, "tarnover.com")     # additionally binds the card to the authenticated domain
doc = store.resolve_discovery("tarnover.com")       # returns the derived DiscoveryDocument
```

A store built with no arguments has an empty allowlist and refuses every registration until `trust_thumbprint(...)` is called — an AgentCard is self-certifying, so without an anchor anyone who could call `register` could assert any domain. The store verifies the extension signature at `register` time and pre-derives a `DiscoveryDocument` so the rest of the AgentPin verification stack (TOFU pinning, revocation, capability validation) runs unchanged. Re-registering the same domain replaces the prior entry, which makes key rotation a single `register` call.

### `A2aAgentCardResolver` — HTTPS pull

For agents that publish their AgentCard at `.well-known/agent-card.json`:

```javascript
import { A2aAgentCardResolver } from 'agentpin';

const resolver = new A2aAgentCardResolver();
const doc = await resolver.resolveDiscovery('tarnover.com');
```

This fetches `https://tarnover.com/.well-known/agent-card.json` (no redirects, 10 s timeout, 1 MiB cap), verifies the extension, cross-checks that the embedded `agentpin_endpoint` host matches the fetched domain, then fetches `https://tarnover.com/.well-known/agent-identity.json` and requires the card key to be published there by thumbprint (spec §4.10.4 step 5) before returning a derived `DiscoveryDocument`. Pass `{ requireDiscoveryBinding: false }` (JS), `require_discovery_binding=False` (Python), `SkipDiscoveryBinding: true` (Go) or `.with_discovery_binding(false)` (Rust) only when another channel establishes the card's provenance. The original card is still accessible via `resolver.lastCard('tarnover.com')` if you need both shapes.

### Composing with the standard resolver chain

The recommended chain for v0.3 deployments is:

```
TrustBundleResolver  →  LocalFileResolver  →  LocalAgentCardStore  →  A2aAgentCardResolver  →  WellKnownResolver
```

Both new resolvers implement the same `DiscoveryResolver` trait as the existing v0.2 resolvers, so they drop into any `ChainResolver` configuration without special casing.

---

## Capability mapping

The AgentCard's `skills[]` array is derived directly from your `AgentDeclaration.capabilities`:

| AgentPin capability | A2A skill `id` |
|---------------------|----------------|
| `read:customers/*`  | `read:customers/*` |
| `write:invoices/*`  | `write:invoices/*` |
| `mcp:tool/calculator` | `mcp:tool/calculator` |

The default `skills[i].name` is the same verb-resource string. Pass a `skills` override to `BuildAndSign` if you want a human-readable display name.

The capability *taxonomy* itself (see [docs/cli-guide.md](cli-guide.md) and §10 of the spec) is unchanged — A2A AgentCards do not introduce new capability semantics; they re-express the existing capability list in A2A's `AgentSkill` shape so A2A-native consumers can read it.

---

## `allowed_domains` and cross-protocol scoping

If your `AgentDeclaration.constraints.allowed_domains` is set, the builder copies it into `capabilities.allowed_domains` on the AgentCard. This is the same allow-list the AgentPin verifier already enforces at credential-verification time (§6.6); copying it onto the AgentCard makes it visible to A2A-native consumers and to the `AllowedDomains` intersection helper that SchemaPin v1.4 `A2aVerificationContext` calls into.

`allowed_domains` is a tri-state: an **absent** field means *unrestricted* (all domains trusted), a present list restricts the agent to the listed literals and `*.` patterns, and an **empty list** means *restricted to nothing*. The builder omits the field entirely when the agent is unrestricted (keeping v0.2-style AgentCards, which never had this field, round-tripping unchanged) and emits `[]` when the constraint is present but empty. The intersection of two disjoint allow-lists is `[]`, which allows nothing — it is never re-interpreted as unrestricted.

---

## Cross-language interop

All four AgentPin SDKs use byte-identical canonicalisation. As of v0.3.0 the release pipeline enforces this by:

- Running 12-way interop tests on every release branch (a card signed in any of Rust/JS/Python/Go must verify in the other three).
- Failing the version-consistency CI check if any SDK reports a different version than the others.

If you build tooling on top of the AgentCard surface and discover a case where one SDK's signed card fails to verify in another, please file an issue at <https://github.com/ThirdKeyAI/AgentPin/issues> — that's a wire-format bug, not a configuration question.
