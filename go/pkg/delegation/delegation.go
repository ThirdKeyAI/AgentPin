// Package delegation creates and verifies AgentPin delegation attestations
// that bind a delegating party (maker or deployer) to a delegatee for a
// fixed capability set (spec §5.6 / §6.4).
//
// An attestation is a signature over the domain-separated structure
//
//	"agentpin-attestation-v1" 0x00 len(domain) domain len(role) role
//	    len(agent_id) agent_id len(delegatee_domain) delegatee_domain
//	    len(delegatee_agent_id) delegatee_agent_id
//	    len(capabilities_hash) capabilities_hash len(kid) kid len(exp) exp
//
// kid binds the attestation to the attesting key; exp (decimal Unix seconds,
// empty when absent) bounds its lifetime.
package delegation

import (
	"crypto/ecdsa"
	"fmt"
	"strconv"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func expString(exp *int64) string {
	if exp == nil {
		return ""
	}
	return strconv.FormatInt(*exp, 10)
}

// CanonicalAttestationInput returns the domain-separated signing input for
// a delegation attestation. Byte-identical across the four SDKs.
func CanonicalAttestationInput(
	domain string,
	role types.DelegationRole,
	agentID string,
	delegateeDomain string,
	delegateeAgentID string,
	capabilities []types.Capability,
	kid string,
	exp *int64,
) []byte {
	return crypto.DomainSeparatedInput(
		crypto.CtxAttestation,
		[]byte(domain),
		[]byte(role),
		[]byte(agentID),
		[]byte(delegateeDomain),
		[]byte(delegateeAgentID),
		[]byte(types.CapabilitiesHash(capabilities)),
		[]byte(kid),
		[]byte(expString(exp)),
	)
}

// CreateAttestation builds and signs a delegation attestation without an
// expiry.
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
	return CreateAttestationWithExpiry(priv, kid, domain, role, agentID, delegateeDomain, delegateeAgentID, capabilities, nil)
}

// CreateAttestationWithExpiry builds and signs a delegation attestation with
// an optional expiry (Unix seconds; nil for none).
func CreateAttestationWithExpiry(
	priv *ecdsa.PrivateKey,
	kid string,
	domain string,
	role types.DelegationRole,
	agentID string,
	delegateeDomain string,
	delegateeAgentID string,
	capabilities []types.Capability,
	exp *int64,
) (*types.DelegationAttestation, error) {
	input := CanonicalAttestationInput(domain, role, agentID, delegateeDomain, delegateeAgentID, capabilities, kid, exp)
	sig, err := crypto.SignBytes(priv, input)
	if err != nil {
		return nil, err
	}
	var expCopy *int64
	if exp != nil {
		v := *exp
		expCopy = &v
	}
	return &types.DelegationAttestation{
		Domain:      domain,
		Role:        role,
		AgentID:     agentID,
		Kid:         kid,
		Attestation: sig,
		Exp:         expCopy,
	}, nil
}

// VerifyAttestation verifies a delegation attestation signature and, when
// present, its expiry.
func VerifyAttestation(
	att *types.DelegationAttestation,
	pub *ecdsa.PublicKey,
	delegateeDomain string,
	delegateeAgentID string,
	capabilities []types.Capability,
) error {
	if att.Exp != nil && *att.Exp < time.Now().Unix() {
		return types.NewVerificationError(
			types.ErrDelegationInvalid,
			fmt.Sprintf("Delegation attestation from %s has expired", att.Domain),
		)
	}
	input := CanonicalAttestationInput(att.Domain, att.Role, att.AgentID, delegateeDomain, delegateeAgentID, capabilities, att.Kid, att.Exp)
	ok, err := crypto.VerifyBytes(pub, input, att.Attestation)
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
