// Package delegation creates and verifies AgentPin delegation attestations
// that bind a delegating party (maker or deployer) to a delegatee for a
// fixed capability set.
package delegation

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// CanonicalAttestationInput returns the canonical signing input for a
// delegation attestation. Format:
//
//	{domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{capabilities_hash}
//
// The role is serialized as "maker" or "deployer" and the capabilities hash
// is computed via types.CapabilitiesHash.
func CanonicalAttestationInput(
	domain string,
	role types.DelegationRole,
	agentID string,
	delegateeDomain string,
	delegateeAgentID string,
	capabilities []types.Capability,
) string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s",
		domain, role, agentID, delegateeDomain, delegateeAgentID,
		types.CapabilitiesHash(capabilities))
}

// CreateAttestation builds and signs a delegation attestation.
func CreateAttestation(
	priv *ecdsa.PrivateKey,
	kid string,
	domain string,
	role types.DelegationRole,
	agentID string,
	delegateeDomain string,
	delegateeAgentID string,
	capabilities []types.Capability,
) (*types.DelegationAttestation, error) {
	input := CanonicalAttestationInput(domain, role, agentID, delegateeDomain, delegateeAgentID, capabilities)
	sig, err := crypto.SignBytes(priv, []byte(input))
	if err != nil {
		return nil, err
	}
	return &types.DelegationAttestation{
		Domain:      domain,
		Role:        role,
		AgentID:     agentID,
		Kid:         kid,
		Attestation: sig,
	}, nil
}

// VerifyAttestation verifies a delegation attestation signature.
func VerifyAttestation(
	att *types.DelegationAttestation,
	pub *ecdsa.PublicKey,
	delegateeDomain string,
	delegateeAgentID string,
	capabilities []types.Capability,
) error {
	input := CanonicalAttestationInput(att.Domain, att.Role, att.AgentID, delegateeDomain, delegateeAgentID, capabilities)
	ok, err := crypto.VerifyBytes(pub, []byte(input), att.Attestation)
	if err != nil {
		return err
	}
	if !ok {
		return types.NewVerificationError(
			types.ErrDelegationInvalid,
			fmt.Sprintf("Delegation attestation from %s failed signature verification", att.Domain),
		)
	}
	return nil
}

// VerifyChainDepth verifies a delegation chain length does not exceed the
// minimum max_delegation_depth across the participating discovery documents.
func VerifyChainDepth(chainLen int, maxDepths []uint8) error {
	min := uint8(0)
	if len(maxDepths) > 0 {
		min = maxDepths[0]
		for _, d := range maxDepths[1:] {
			if d < min {
				min = d
			}
		}
	}
	if chainLen > int(min) {
		return types.NewVerificationError(
			types.ErrDelegationDepthExceeded,
			fmt.Sprintf("Delegation chain depth %d exceeds minimum max_delegation_depth %d", chainLen, min),
		)
	}
	return nil
}
