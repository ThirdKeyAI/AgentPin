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
