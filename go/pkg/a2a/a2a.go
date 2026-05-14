// Package a2a builds and verifies A2A AgentCards with the AgentPin
// cryptographic-identity extension (v0.3.0).
//
// Wire-compatible with the Rust, JavaScript, and Python ports: cards signed
// in any language verify cleanly in the others. Signing input is the
// canonical bytes of the AgentCard with the `agentpin` field cleared
// (sorted-key JSON, compact separators, no whitespace).
package a2a

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// BuildOptions controls optional fields when constructing an unsigned card.
type BuildOptions struct {
	// Skills overrides the auto-generated skill list. When empty, capabilities
	// in the declaration are mapped 1:1 to skills via
	// types.CapabilityToSkill.
	Skills            []types.A2aAgentSkill
	Streaming         bool
	PushNotifications bool
}

// BuildUnsignedAgentCard maps an AgentPin AgentDeclaration to a minimal A2A
// AgentCard (no extension). Capabilities map 1:1 to skills; the
// allowed_domains constraint is copied into capabilities.allowed_domains.
func BuildUnsignedAgentCard(url string, declaration *types.AgentDeclaration, opts BuildOptions) types.A2aAgentCard {
	var skills []types.A2aAgentSkill
	if len(opts.Skills) > 0 {
		skills = append(skills, opts.Skills...)
	} else {
		skills = make([]types.A2aAgentSkill, 0, len(declaration.Capabilities))
		for _, cap := range declaration.Capabilities {
			skills = append(skills, types.CapabilityToSkill(cap))
		}
	}

	allowed := types.AllowedDomainsHelper.FromConstraints(declaration.Constraints)
	caps := types.A2aAgentCapabilities{
		Streaming:         opts.Streaming,
		PushNotifications: opts.PushNotifications,
	}
	if !types.AllowedDomainsHelper.IsUnrestricted(allowed) {
		caps.AllowedDomains = allowed
	}

	return types.A2aAgentCard{
		Name:         declaration.Name,
		Description:  declaration.Description,
		Version:      declaration.Version,
		URL:          url,
		Capabilities: caps,
		Skills:       skills,
	}
}

// SignAgentCard signs the canonical bytes of `unsigned` (with the extension
// cleared) using the PEM-encoded private key and writes the AgentpinExtension
// payload onto a copy of the card.
func SignAgentCard(unsigned types.A2aAgentCard, privateKeyPEM, kid, agentpinEndpoint string) (types.A2aAgentCard, error) {
	if agentpinEndpoint == "" {
		return types.A2aAgentCard{}, types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"SignAgentCard requires agentpin_endpoint",
		)
	}
	priv, err := crypto.LoadPrivateKey(privateKeyPEM)
	if err != nil {
		return types.A2aAgentCard{}, err
	}

	// Build the canonical signing input from the unsigned card.
	signing := unsigned
	signing.Agentpin = nil
	canonical, err := canonicalizeCard(signing)
	if err != nil {
		return types.A2aAgentCard{}, err
	}

	signature, err := crypto.SignBytes(priv, canonical)
	if err != nil {
		return types.A2aAgentCard{}, err
	}

	pubPEM, err := crypto.MarshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return types.A2aAgentCard{}, err
	}
	publicJWK, err := jwk.PEMToJWK(pubPEM, kid)
	if err != nil {
		return types.A2aAgentCard{}, err
	}

	signed := unsigned
	signed.Agentpin = &types.AgentpinExtension{
		AgentpinEndpoint: agentpinEndpoint,
		PublicKeyJWK:     publicJWK,
		Signature:        signature,
	}
	return signed, nil
}

// BuildAndSignAgentCard is a one-shot helper combining BuildUnsignedAgentCard
// and SignAgentCard.
func BuildAndSignAgentCard(
	url string,
	declaration *types.AgentDeclaration,
	privateKeyPEM, kid, agentpinEndpoint string,
	opts BuildOptions,
) (types.A2aAgentCard, error) {
	unsigned := BuildUnsignedAgentCard(url, declaration, opts)
	return SignAgentCard(unsigned, privateKeyPEM, kid, agentpinEndpoint)
}

// VerifyAgentpinExtension verifies the signature in card.Agentpin against the
// JWK embedded in the same extension. Returns nil on success or a
// VerificationError(ErrDiscoveryInvalid) on any failure (missing extension,
// malformed JWK, signature mismatch).
//
// This proves only that the card has not been tampered with relative to the
// key inside its own extension. The caller still has to verify the JWK
// chains back to a trusted AgentPin discovery document.
func VerifyAgentpinExtension(card *types.A2aAgentCard) error {
	if card == nil || card.Agentpin == nil {
		return types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"AgentCard has no agentpin extension",
		)
	}
	withoutExt := *card
	withoutExt.Agentpin = nil
	canonical, err := canonicalizeCard(withoutExt)
	if err != nil {
		return err
	}
	pubPEM, err := jwk.JWKToPEM(&card.Agentpin.PublicKeyJWK)
	if err != nil {
		return err
	}
	ok, err := crypto.VerifySignature(pubPEM, canonical, card.Agentpin.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return types.NewVerificationError(
			types.ErrDiscoveryInvalid,
			"A2A AgentCard signature did not verify against extension JWK",
		)
	}
	return nil
}

// ExtensionKeyThumbprint returns the JWK thumbprint of the public key
// embedded in an AgentpinExtension.
func ExtensionKeyThumbprint(ext *types.AgentpinExtension) string {
	return jwk.JWKThumbprint(&ext.PublicKeyJWK)
}

// CanonicalizeForSigning produces the byte-identical canonical signing input
// for an AgentCard: sorted-key JSON, compact separators, "null"/empty fields
// dropped via the struct's omitempty annotations. Cross-language byte-equal
// to the Rust SDK's canonicalisation.
func CanonicalizeForSigning(value interface{}) ([]byte, error) {
	return canonicalize(value)
}

// canonicalizeCard re-serialises an AgentCard with sorted object keys so the
// signature input is byte-identical with the Rust, JS, and Python SDKs.
func canonicalizeCard(card types.A2aAgentCard) ([]byte, error) {
	return canonicalize(card)
}

// canonicalize re-marshals the value through map[string]interface{}, which
// Go's encoding/json sorts alphabetically by key — producing byte-identical
// output to the Rust SDK's BTreeMap-based canonicalisation.
func canonicalize(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("unmarshal for canonicalisation: %w", err)
	}
	out, err := json.Marshal(generic)
	if err != nil {
		return nil, fmt.Errorf("re-marshal: %w", err)
	}
	return out, nil
}

// ErrNoExtension is reported by helpers that require a signed card. Kept as a
// distinct sentinel for callers who prefer errors.Is to ErrorCode matching.
var ErrNoExtension = errors.New("AgentCard has no agentpin extension")
