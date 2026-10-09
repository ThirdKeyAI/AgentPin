// Package bundle provides helpers for constructing and querying AgentPin
// trust bundles for offline / air-gapped verification.
package bundle

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// NewTrustBundle creates an empty trust bundle with the given creation
// timestamp.
func NewTrustBundle(createdAt string) types.TrustBundle {
	return types.TrustBundle{
		AgentpinBundleVersion: version.BundleVersion,
		CreatedAt:             createdAt,
		Documents:             []types.DiscoveryDocument{},
		Revocations:           []types.RevocationDocument{},
	}
}

// FindBundleDiscovery returns the first discovery document in b matching domain.
func FindBundleDiscovery(b *types.TrustBundle, domain string) *types.DiscoveryDocument {
	return b.FindDiscovery(domain)
}

// FindBundleRevocation returns the first revocation document in b matching domain.
func FindBundleRevocation(b *types.TrustBundle, domain string) *types.RevocationDocument {
	return b.FindRevocation(domain)
}

// BundleSigningInput is the agentpin-bundle-v1 context over the canonical
// JSON of b with Signature cleared (design issue 5).
func BundleSigningInput(b *types.TrustBundle) ([]byte, error) {
	cp := *b
	cp.Signature = ""
	canonical, err := a2a.CanonicalizeForSigning(cp)
	if err != nil {
		return nil, err
	}
	return crypto.DomainSeparatedInput(crypto.CtxBundle, canonical), nil
}

// SignTrustBundle signs b with the operator key identified by kid.
func SignTrustBundle(b *types.TrustBundle, priv *ecdsa.PrivateKey, kid string) error {
	b.Kid = kid
	b.Signature = ""
	input, err := BundleSigningInput(b)
	if err != nil {
		return err
	}
	sig, err := crypto.SignBytes(priv, input)
	if err != nil {
		return err
	}
	b.Signature = sig
	return nil
}

// VerifyTrustBundle verifies b's signature under pub and rejects it when
// ExpiresAt has passed. Unsigned bundles are rejected.
func VerifyTrustBundle(b *types.TrustBundle, pub *ecdsa.PublicKey) error {
	if b.Signature == "" {
		return errors.New("trust bundle is not signed")
	}
	input, err := BundleSigningInput(b)
	if err != nil {
		return err
	}
	ok, err := crypto.VerifyBytes(pub, input, b.Signature)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("trust bundle signature did not verify")
	}
	return CheckBundleExpiry(b)
}

// CheckBundleExpiry rejects a bundle whose ExpiresAt is unparsable or past.
func CheckBundleExpiry(b *types.TrustBundle) error {
	if b.ExpiresAt == "" {
		return nil
	}
	exp, err := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil {
		return errors.New("trust bundle expires_at is not RFC 3339")
	}
	if exp.Unix() < time.Now().Unix() {
		return errors.New("trust bundle has expired")
	}
	return nil
}
