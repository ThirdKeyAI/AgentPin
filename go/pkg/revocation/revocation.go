// Package revocation builds revocation documents and provides revocation
// checks against credential / agent / key identifiers.
package revocation

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
	"github.com/ThirdKeyAi/agentpin/go/pkg/a2a"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
	"github.com/ThirdKeyAi/agentpin/go/pkg/fetch"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// BuildRevocationDocument creates an empty revocation document for entity.
func BuildRevocationDocument(entity string) types.RevocationDocument {
	return types.RevocationDocument{
		AgentpinVersion:    version.ProtocolVersion,
		Entity:             entity,
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
		RevokedCredentials: []types.RevokedCredential{},
		RevokedAgents:      []types.RevokedAgent{},
		RevokedKeys:        []types.RevokedKey{},
	}
}

// AddRevokedCredential records jti as revoked with the given reason.
func AddRevokedCredential(doc *types.RevocationDocument, jti string, reason types.RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedCredentials = append(doc.RevokedCredentials, types.RevokedCredential{
		Jti:       jti,
		RevokedAt: now,
		Reason:    reason,
	})
	doc.UpdatedAt = now
}

// AddRevokedAgent records agentID as revoked with the given reason.
func AddRevokedAgent(doc *types.RevocationDocument, agentID string, reason types.RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedAgents = append(doc.RevokedAgents, types.RevokedAgent{
		AgentID:   agentID,
		RevokedAt: now,
		Reason:    reason,
	})
	doc.UpdatedAt = now
}

// AddRevokedKey records kid as revoked with the given reason.
func AddRevokedKey(doc *types.RevocationDocument, kid string, reason types.RevocationReason) {
	now := time.Now().UTC().Format(time.RFC3339)
	doc.RevokedKeys = append(doc.RevokedKeys, types.RevokedKey{
		Kid:       kid,
		RevokedAt: now,
		Reason:    reason,
	})
	doc.UpdatedAt = now
}

// CheckRevocation returns a typed VerificationError if the credential, agent,
// or key is on the revocation list.
func CheckRevocation(doc *types.RevocationDocument, jti, agentID, kid string) error {
	for _, rc := range doc.RevokedCredentials {
		if rc.Jti == jti {
			return types.NewVerificationError(
				types.ErrCredentialRevoked,
				fmt.Sprintf("Credential %s revoked: %s", jti, rc.Reason),
			)
		}
	}
	for _, ra := range doc.RevokedAgents {
		if ra.AgentID == agentID {
			return types.NewVerificationError(
				types.ErrAgentInactive,
				fmt.Sprintf("Agent %s revoked: %s", agentID, ra.Reason),
			)
		}
	}
	for _, rk := range doc.RevokedKeys {
		if rk.Kid == kid {
			return types.NewVerificationError(
				types.ErrKeyRevoked,
				fmt.Sprintf("Key %s revoked: %s", kid, rk.Reason),
			)
		}
	}
	return nil
}

// FetchRevocationDocument fetches a revocation document from url. Any
// failure, including HTTP 404, is an error so callers fail closed for an
// explicitly declared endpoint.
func FetchRevocationDocument(client *http.Client, url string) (*types.RevocationDocument, error) {
	doc, err := FetchRevocationDocumentIfPresent(client, url)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("HTTP 404 fetching %s", url)
	}
	return doc, nil
}

// FetchRevocationDocumentIfPresent fetches a revocation document, returning
// (nil, nil) on HTTP 404. Used for the spec §8.1 default endpoint when the
// discovery document declares none: an issuer that publishes no revocation
// document is not an error, but any other failure still fails closed.
func FetchRevocationDocumentIfPresent(client *http.Client, url string) (*types.RevocationDocument, error) {
	// Only https URLs with a domain host are ever fetched (AP-12). Same-host
	// binding to the issuer is enforced by the caller / discovery validation.
	if _, err := domain.HTTPSURLHost(url); err != nil {
		return nil, err
	}
	body, found, err := fetch.JSONBounded(client, url, 0)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	var doc types.RevocationDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON from %s", url)
	}
	return &doc, nil
}

// RevocationSigningInput is the agentpin-revocation-v1 context over the
// canonical JSON of doc with signature cleared (design issue 3).
func RevocationSigningInput(doc *types.RevocationDocument) ([]byte, error) {
	cp := *doc
	cp.Signature = ""
	canonical, err := a2a.CanonicalizeForSigning(cp)
	if err != nil {
		return nil, err
	}
	return crypto.DomainSeparatedInput(crypto.CtxRevocation, canonical), nil
}

// SignRevocationDocument signs doc with a discovery-document key.
func SignRevocationDocument(doc *types.RevocationDocument, priv *ecdsa.PrivateKey, kid string) error {
	doc.Kid = kid
	doc.Signature = ""
	input, err := RevocationSigningInput(doc)
	if err != nil {
		return err
	}
	sig, err := crypto.SignBytes(priv, input)
	if err != nil {
		return err
	}
	doc.Signature = sig
	return nil
}

// VerifyRevocationDocument validates doc against the discovery document it
// belongs to: wire version, entity binding, and (when present) its
// signature under a key from disc.PublicKeys.
func VerifyRevocationDocument(doc *types.RevocationDocument, disc *types.DiscoveryDocument) error {
	if doc.AgentpinVersion != version.ProtocolVersion {
		return fmt.Errorf("unsupported revocation document version: %s", doc.AgentpinVersion)
	}
	docEntity, err := domain.Normalize(doc.Entity)
	if err != nil {
		return fmt.Errorf("invalid revocation entity: %w", err)
	}
	discEntity, err := domain.Normalize(disc.Entity)
	if err != nil {
		return fmt.Errorf("invalid discovery entity: %w", err)
	}
	if docEntity != discEntity {
		return fmt.Errorf("revocation document entity '%s' does not match discovery entity '%s'", doc.Entity, disc.Entity)
	}
	if doc.Signature != "" {
		if doc.Kid == "" {
			return errors.New("signed revocation document has no kid")
		}
		var key *types.JWK
		for i := range disc.PublicKeys {
			if disc.PublicKeys[i].Kid == doc.Kid {
				key = &disc.PublicKeys[i]
				break
			}
		}
		if key == nil {
			return fmt.Errorf("revocation document kid '%s' not found in discovery document", doc.Kid)
		}
		pub, err := jwk.JWKToVerifyingKey(key)
		if err != nil {
			return err
		}
		input, err := RevocationSigningInput(doc)
		if err != nil {
			return err
		}
		ok, err := crypto.VerifyBytes(pub, input, doc.Signature)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("revocation document signature did not verify")
		}
	}
	return nil
}

// CheckRevocationFreshness rejects a document whose updated_at is
// unparsable or older than maxAgeSecs.
func CheckRevocationFreshness(doc *types.RevocationDocument, maxAgeSecs int64) error {
	updated, err := time.Parse(time.RFC3339, doc.UpdatedAt)
	if err != nil {
		return errors.New("revocation document updated_at is not RFC 3339")
	}
	age := time.Now().Unix() - updated.Unix()
	if age > maxAgeSecs {
		return fmt.Errorf("revocation document is stale (%d seconds old, max %d)", age, maxAgeSecs)
	}
	return nil
}
