// Package credential issues AgentPin credential JWTs and validates credential
// capability declarations against discovery documents.
package credential

import (
	"crypto/ecdsa"
	"time"

	"github.com/google/uuid"

	"github.com/ThirdKeyAi/agentpin/go/internal/version"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// IssueCredential issues a new agent credential JWT signed by priv. The
// returned compact JWT carries header alg=ES256 / typ=agentpin-credential+jwt
// — anything else would be rejected by the verifier.
//
// audience may be empty (omits the "aud" claim). delegationChain may be nil.
func IssueCredential(
	priv *ecdsa.PrivateKey,
	kid string,
	issuer string,
	agentID string,
	audience string,
	capabilities []types.Capability,
	constraints *types.Constraints,
	delegationChain []types.DelegationAttestation,
	ttlSecs uint64,
) (string, error) {
	return issue(priv, kid, issuer, agentID, audience, capabilities, constraints, delegationChain, ttlSecs, nil)
}

// IssueBoundCredential issues a credential bound to the agent's Web Bot
// Auth key: wbaJkt (its JWK thumbprint, see wba.Thumbprint) is carried as
// cnf.jkt (spec §18).
func IssueBoundCredential(
	priv *ecdsa.PrivateKey,
	kid string,
	issuer string,
	agentID string,
	audience string,
	capabilities []types.Capability,
	constraints *types.Constraints,
	delegationChain []types.DelegationAttestation,
	ttlSecs uint64,
	wbaJkt string,
) (string, error) {
	return issue(priv, kid, issuer, agentID, audience, capabilities, constraints, delegationChain, ttlSecs,
		&types.Confirmation{Jkt: wbaJkt})
}

func issue(
	priv *ecdsa.PrivateKey,
	kid string,
	issuer string,
	agentID string,
	audience string,
	capabilities []types.Capability,
	constraints *types.Constraints,
	delegationChain []types.DelegationAttestation,
	ttlSecs uint64,
	cnf *types.Confirmation,
) (string, error) {
	if capabilities == nil {
		capabilities = []types.Capability{}
	}
	now := time.Now().Unix()
	header := &types.JWTHeader{
		Alg: jwt.RequiredAlg,
		Typ: jwt.RequiredTyp,
		Kid: kid,
	}
	payload := &types.JWTPayload{
		Iss:             issuer,
		Sub:             agentID,
		Aud:             audience,
		Iat:             now,
		Exp:             now + int64(ttlSecs),
		Jti:             uuid.NewString(),
		AgentpinVersion: version.ProtocolVersion,
		Capabilities:    capabilities,
		Constraints:     constraints,
		DelegationChain: delegationChain,
		Cnf:             cnf,
	}
	if err := jwt.ValidateClaims(payload); err != nil {
		return "", err
	}
	return jwt.EncodeJWT(header, payload, priv)
}

// ValidateCredentialAgainstDiscovery checks that the credential's capability
// declarations are a subset of (covered by) the agent's discovery
// declarations.
func ValidateCredentialAgainstDiscovery(credentialCaps, discoveryCaps []types.Capability) error {
	if !types.CapabilitiesSubset(discoveryCaps, credentialCaps) {
		return types.NewVerificationError(
			types.ErrCapabilityExceeded,
			"Credential capabilities exceed discovery document",
		)
	}
	return nil
}
