# AgentPin Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/ThirdKeyAi/agentpin/go.svg)](https://pkg.go.dev/github.com/ThirdKeyAi/agentpin/go)

Go implementation of the AgentPin domain-anchored cryptographic identity
protocol for AI agents. Wire-compatible with the
[Rust](../crates/agentpin), [JavaScript](../javascript), and
[Python](../python) SDKs.

Part of the ThirdKey trust stack: [SchemaPin](https://schemapin.org) →
**AgentPin** → [Symbiont](https://symbiont.dev).

## Install

```bash
# Library
go get github.com/ThirdKeyAi/agentpin/go

# CLI
go install github.com/ThirdKeyAi/agentpin/go/cmd/agentpin@latest
```

Requires Go 1.21+.

## Quick start

```go
package main

import (
	"fmt"
	"log"

	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"github.com/ThirdKeyAi/agentpin/go/pkg/verification"
)

func main() {
	// 1. Generate a keypair.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	priv, _ := crypto.LoadPrivateKey(kp.PrivateKeyPEM)
	pub, _ := crypto.LoadPublicKey(kp.PublicKeyPEM)

	// 2. Build a discovery document.
	disc := discovery.BuildDiscoveryDocument(
		"example.com",
		types.EntityMaker,
		[]types.JWK{jwk.VerifyingKeyToJWK(pub, "example-2026-01")},
		[]types.AgentDeclaration{
			{
				AgentID:      "urn:agentpin:example.com:my-agent",
				Name:         "My Agent",
				Capabilities: []types.Capability{"read:data"},
				Status:       types.AgentActive,
			},
		},
		2, // max_delegation_depth
		"2026-01-15T00:00:00Z",
	)

	// 3. Issue a credential.
	cred, err := credential.IssueCredential(
		priv, "example-2026-01",
		"example.com", "urn:agentpin:example.com:my-agent",
		"verifier.com",
		[]types.Capability{"read:data"},
		nil, nil,
		3600, // ttl_secs
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("credential:", cred[:60], "...")

	// 4. Verify it offline.
	pinStore := pinning.NewKeyPinStore()
	result := verification.VerifyCredentialOffline(
		cred, &disc, nil, pinStore,
		"verifier.com",
		verification.DefaultVerifierConfig(),
	)
	if !result.Valid {
		log.Fatalf("verify failed: %s", result.ErrorMessage)
	}
	fmt.Println("verified agent:", result.AgentID)
}
```

## CLI

The `agentpin` CLI mirrors the Rust binary:

```bash
agentpin keygen --domain example.com --kid example-2026-01 --output-dir ./keys
agentpin issue \
  --private-key ./keys/example-2026-01.private.pem \
  --kid example-2026-01 \
  --issuer example.com \
  --agent-id urn:agentpin:example.com:my-agent \
  --capabilities read:data,write:report \
  --ttl 3600
agentpin verify \
  --credential <jwt-string-or-path> \
  --discovery ./discovery.json \
  --offline
agentpin bundle \
  --discovery ./d1.json --discovery ./d2.json \
  --output trust-bundle.json
```

## Language API reference

| Function (Go)                                           | Rust equivalent                                | Purpose                              |
|---------------------------------------------------------|------------------------------------------------|--------------------------------------|
| `crypto.GenerateKeyPair`                                | `agentpin::crypto::generate_key_pair`          | New ECDSA P-256 keypair (PEM)        |
| `crypto.SignData` / `VerifySignature`                   | `sign_data` / `verify_signature`               | DER-signature over arbitrary bytes   |
| `crypto.GenerateKeyID`                                  | `generate_key_id`                              | SHA-256 hex of SPKI DER              |
| `jwk.PEMToJWK` / `JWKToPEM`                             | `jwk::pem_to_jwk` / `jwk_to_pem`               | PEM ↔ JWK conversion                 |
| `jwk.JWKThumbprint`                                     | `jwk_thumbprint`                               | RFC 7638 thumbprint                  |
| `jwt.EncodeJWT` / `VerifyJWT` / `DecodeJWTUnverified`   | `jwt::encode_jwt` / `verify_jwt`               | ES256-only JWT (rejects all else)    |
| `discovery.BuildDiscoveryDocument`                      | `discovery::build_discovery_document`          | Build `.well-known/agent-identity`   |
| `discovery.FetchDiscoveryDocument`                      | `discovery::fetch_discovery_document` (fetch)  | HTTPS fetch (no redirects)           |
| `credential.IssueCredential`                            | `credential::issue_credential`                 | Issue agent credential JWT           |
| `verification.VerifyCredentialOffline`                  | `verification::verify_credential_offline`      | 12-step offline verifier             |
| `verification.VerifyCredentialWithResolver`             | `verification::verify_credential_with_resolver`| Verify via DiscoveryResolver         |
| `revocation.BuildRevocationDocument` / `CheckRevocation`| `revocation::*`                                | Build / query revocations            |
| `pinning.KeyPinStore`                                   | `pinning::KeyPinStore`                         | TOFU key pin store                   |
| `delegation.CreateAttestation` / `VerifyAttestation`    | `delegation::*`                                | Maker→deployer attestation chain     |
| `mutual.CreateChallenge` / `VerifyResponse`             | `mutual::*`                                    | 128-bit nonce challenge / response   |
| `nonce.InMemoryStore`                                   | `nonce::InMemoryNonceStore`                    | Replay-protection nonce store        |
| `bundle.NewTrustBundle`                                 | `types::bundle::TrustBundle::new`              | Offline trust-bundle builder         |
| `resolver.{WellKnown,LocalFile,TrustBundle,Chain}Resolver` | `resolver::*`                              | Pluggable discovery resolution       |
| `a2a.BuildAndSignAgentCard` / `VerifyAgentpinExtension` | `a2a::A2aAgentCardBuilder` / `verify_agentpin_extension` | (v0.3) Sign + verify A2A AgentCards |
| `dns.ParseTxtRecord` / `VerifyDnsMatch` / `LookupTxt`   | `dns::parse_txt_record` / `verify_dns_match` / `fetch_dns_txt` | (v0.3) DNS TXT cross-verification |
| `resolver.LocalAgentCardStore`                          | `resolver_local::LocalAgentCardStore`          | (v0.3) Push-registered AgentCard store |
| `resolver.A2aAgentCardResolver`                         | `resolver_a2a::A2aAgentCardResolver`           | (v0.3) `.well-known/agent-card.json` fetcher |
| `types.AllowedDomainsHelper`                            | `types::discovery::AllowedDomains`             | (v0.3) Cross-protocol allow-list helpers |

## Security guarantees

- **ES256 only.** `jwt.DecodeJWTUnverified` rejects every algorithm except
  `ES256` and every typ except `agentpin-credential+jwt` *before* any
  signature work. There is no third-party JWT dependency with permissive
  `alg` defaults — we use `crypto/ecdsa` directly.
- **Wire compatibility.** Discovery documents, credentials, revocation lists,
  and trust bundles round-trip byte-identically across the Rust, JavaScript,
  Python, and Go SDKs. This is asserted by cross-language interop tests in
  `pkg/verification/cross_language_test.go`.
- **TOFU key pinning.** Verification fail-closes on key change unless the
  caller explicitly trusts the rotation via `KeyPinStore.AddKey`.
- **Fail-closed revocation.** When a resolver returns an error fetching a
  revocation document, verification rejects the credential rather than
  proceeding without revocation data.
- **(v0.3) AgentCard canonicalisation.** The `a2a.BuildAndSignAgentCard` /
  `a2a.VerifyAgentpinExtension` pair uses sorted-key compact JSON with the
  `agentpin` field cleared as the signing input — byte-identical to the
  other three SDKs. AgentCards signed in any SDK verify in Go.
- **(v0.3) DNS TXT fail-closed.** When a `_agentpin.{domain}` TXT record is
  present, `dns.VerifyDnsMatch` rejects mismatches with `DISCOVERY_INVALID`.
  Absent records are inert.

## v0.3 quick reference

```go
// Sign an A2A AgentCard
card, _ := a2a.BuildAndSignAgentCard(
    "https://example.com/agent", &declaration,
    privateKeyPEM, "example-2026-05",
    "https://example.com/.well-known/agent-identity.json",
    a2a.BuildOptions{Streaming: true},
)

// Verify (extension signature only)
_ = a2a.VerifyAgentpinExtension(&card)

// Push-based discovery
store := resolver.NewLocalAgentCardStore()
_ = store.Register(card)
doc, _ := store.ResolveDiscovery("example.com")

// Pull-based discovery
r := resolver.NewA2aAgentCardResolver()
doc, _ = r.ResolveDiscovery("example.com")

// DNS TXT cross-verification
record, _ := dns.ParseTxtRecord("v=agentpin1; kid=example-2026-05; fp=sha256:abcd...")
_ = dns.VerifyDnsMatch(&doc, record)
```

See [docs/a2a-agentcards.md](https://github.com/ThirdKeyAI/AgentPin/blob/main/docs/a2a-agentcards.md) for the full guide.

## Development

```bash
cd go
go test ./...      # all packages green
go vet ./...       # no findings
gofmt -l .         # must be empty
```

To regenerate cross-language test fixtures from the Rust CLI:

```bash
cargo build -p agentpin-cli --release
target/release/agentpin keygen \
  --domain example.com --kid example-2026-01 \
  --output-dir go/pkg/verification/testdata --format both
# Then update go/pkg/verification/testdata/discovery.json with the new JWK
# and reissue go/pkg/verification/testdata/credential.jwt accordingly.
```

## License

MIT — see [LICENSE](../LICENSE).
