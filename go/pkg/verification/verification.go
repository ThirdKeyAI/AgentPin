// Package verification implements the AgentPin 12-step credential
// verification flow defined in the spec. The flow is preserved verbatim
// from the Rust SDK: any change here should be mirrored in Rust / JS /
// Python.
//
// 12-step flow:
//
//  1. JWT structure parse
//  2. Header alg validation (ES256 only — REJECT others)
//  3. Signature verify
//  4. Issuer domain extraction
//  5. Discovery document resolution (caller-provided or via resolver)
//  6. Domain binding verify (issuer claim matches discovery entity)
//  7. Key matching (sig kid maps to discovery key)
//  8. TOFU key pinning check
//  9. Expiration validation (`exp` claim)
//  10. Revocation checking (credential id, agent id, key id)
//  11. Capability validation (credential capabilities subset of declaration)
//  12. Delegation chain verification (if `del`/`delegation_chain` present)
package verification

import (
	"fmt"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/revocation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// VerifierConfig tunes verification behaviour.
type VerifierConfig struct {
	// ClockSkewSecs is the tolerance for iat/exp comparisons (default: 60).
	ClockSkewSecs int64
	// MaxTTLSecs caps the maximum credential lifetime (default: 86400).
	MaxTTLSecs int64
	// StrictCapabilities, when true, validates capabilities against the
	// taxonomy (currently informational; reserved for future use).
	StrictCapabilities bool
}

// DefaultVerifierConfig returns the default verifier configuration.
func DefaultVerifierConfig() VerifierConfig {
	return VerifierConfig{
		ClockSkewSecs:      60,
		MaxTTLSecs:         86400,
		StrictCapabilities: false,
	}
}

// DelegationChainEntry summarizes one delegation attestation in the result.
type DelegationChainEntry struct {
	Domain   string `json:"domain"`
	Role     string `json:"role"`
	Verified bool   `json:"verified"`
}

// KeyPinningStatus summarizes the TOFU pinning outcome.
type KeyPinningStatus struct {
	Status    string `json:"status"`
	FirstSeen string `json:"first_seen,omitempty"`
}

// Result is the structured verification outcome.
type Result struct {
	Valid              bool                   `json:"valid"`
	AgentID            string                 `json:"agent_id,omitempty"`
	Issuer             string                 `json:"issuer,omitempty"`
	Capabilities       []types.Capability     `json:"capabilities,omitempty"`
	Constraints        *types.Constraints     `json:"constraints,omitempty"`
	DelegationVerified *bool                  `json:"delegation_verified,omitempty"`
	DelegationChain    []DelegationChainEntry `json:"delegation_chain,omitempty"`
	KeyPinning         *KeyPinningStatus      `json:"key_pinning,omitempty"`
	ErrorCode          types.ErrorCode        `json:"error_code,omitempty"`
	ErrorMessage       string                 `json:"error_message,omitempty"`
	Warnings           []string               `json:"warnings,omitempty"`
}

func failure(code types.ErrorCode, msg string) Result {
	return Result{Valid: false, ErrorCode: code, ErrorMessage: msg, Warnings: []string{}}
}

// VerifyCredentialOffline runs the full 12-step verification flow against a
// caller-provided discovery (and optional revocation) document.
func VerifyCredentialOffline(
	credentialJWT string,
	disc *types.DiscoveryDocument,
	rev *types.RevocationDocument,
	pinStore *pinning.KeyPinStore,
	audience string,
	config VerifierConfig,
) Result {
	// Steps 1-2: Parse JWT (alg/typ enforced inside DecodeJWTUnverified).
	header, payload, _, err := jwt.DecodeJWTUnverified(credentialJWT)
	if err != nil {
		return failure(types.ErrAlgorithmRejected, fmt.Sprintf("JWT parse failed: %v", err))
	}

	// Step 9: Temporal validity (also covered by spec step "expiration").
	now := time.Now().Unix()
	skew := config.ClockSkewSecs

	if payload.Iat > now+skew {
		return failure(types.ErrCredentialExpired, "Credential issued in the future")
	}
	if payload.Exp <= now-skew {
		return failure(types.ErrCredentialExpired, "Credential has expired")
	}
	if payload.Nbf != nil {
		if *payload.Nbf > now+skew {
			return failure(types.ErrCredentialExpired, "Credential not yet valid (nbf)")
		}
	}
	lifetime := payload.Exp - payload.Iat
	if lifetime > config.MaxTTLSecs {
		return failure(
			types.ErrCredentialExpired,
			fmt.Sprintf("Credential lifetime %d exceeds max TTL %d", lifetime, config.MaxTTLSecs),
		)
	}

	// Steps 5-6: Validate discovery document (entity matches iss).
	if err := discovery.ValidateDiscoveryDocument(disc, payload.Iss); err != nil {
		return failure(types.ErrDiscoveryInvalid, fmt.Sprintf("Discovery validation failed: %v", err))
	}

	// Step 7: Resolve public key by kid.
	kk := discovery.FindKeyByKid(disc, header.Kid)
	if kk == nil {
		return failure(types.ErrKeyNotFound, fmt.Sprintf("Key '%s' not found in discovery document", header.Kid))
	}
	if kk.Exp != "" {
		if expDt, err := time.Parse(time.RFC3339, kk.Exp); err == nil {
			if expDt.Unix() < now-skew {
				return failure(types.ErrKeyExpired, fmt.Sprintf("Key '%s' has expired", header.Kid))
			}
		}
	}
	pub, err := jwk.JWKToVerifyingKey(kk)
	if err != nil {
		return failure(types.ErrKeyNotFound, fmt.Sprintf("Invalid key format for '%s': %v", header.Kid, err))
	}

	// Step 3: Verify JWT signature.
	if _, _, err := jwt.VerifyJWT(credentialJWT, pub); err != nil {
		return failure(types.ErrSignatureInvalid, fmt.Sprintf("JWT signature verification failed for kid '%s'", header.Kid))
	}

	// Step 10: Revocation.
	if rev != nil {
		if err := revocation.CheckRevocation(rev, payload.Jti, payload.Sub, header.Kid); err != nil {
			if ve, ok := types.AsVerificationError(err); ok {
				return failure(ve.Code, ve.Message)
			}
			return failure(types.ErrCredentialRevoked, err.Error())
		}
	}

	// Agent presence + status.
	agent := discovery.FindAgentByID(disc, payload.Sub)
	if agent == nil {
		return failure(types.ErrAgentNotFound, fmt.Sprintf("Agent '%s' not found in discovery document", payload.Sub))
	}
	if agent.Status != types.AgentActive {
		return failure(types.ErrAgentInactive, fmt.Sprintf("Agent '%s' status is %s", payload.Sub, agent.Status))
	}

	// Step 11: Capability subset.
	if err := credential.ValidateCredentialAgainstDiscovery(payload.Capabilities, agent.Capabilities); err != nil {
		return failure(types.ErrCapabilityExceeded, err.Error())
	}

	// Constraints subset.
	if !types.ConstraintsSubsetOf(agent.Constraints, payload.Constraints) {
		return failure(types.ErrConstraintViolation, "Credential constraints are less restrictive than discovery defaults")
	}

	// Build success result; pinning + delegation populated below.
	result := Result{
		Valid:        true,
		AgentID:      payload.Sub,
		Issuer:       payload.Iss,
		Capabilities: payload.Capabilities,
		Constraints:  payload.Constraints,
		Warnings:     []string{},
	}

	// Step 12: Delegation chain (offline mode cannot verify signatures).
	if len(payload.DelegationChain) > 0 {
		entries := make([]DelegationChainEntry, 0, len(payload.DelegationChain))
		for _, att := range payload.DelegationChain {
			entries = append(entries, DelegationChainEntry{
				Domain:   att.Domain,
				Role:     string(att.Role),
				Verified: false,
			})
		}
		result.DelegationChain = entries
		f := false
		result.DelegationVerified = &f
		result.Warnings = append(result.Warnings, "Delegation chain present but not verified in offline mode")
	}

	// Step 8: TOFU key pinning.
	pr, perr := pinning.CheckPinning(pinStore, payload.Iss, kk)
	if perr != nil {
		return failure(types.ErrKeyPinMismatch, fmt.Sprintf("Key for '%s' has changed since last pinned", payload.Iss))
	}
	switch pr {
	case pinning.ResultFirstUse:
		result.KeyPinning = &KeyPinningStatus{
			Status:    "first_use",
			FirstSeen: time.Now().UTC().Format(time.RFC3339),
		}
	case pinning.ResultMatched:
		var first string
		if pd := pinStore.GetDomain(payload.Iss); pd != nil && len(pd.PinnedKeys) > 0 {
			first = pd.PinnedKeys[0].FirstSeen
		}
		result.KeyPinning = &KeyPinningStatus{Status: "pinned", FirstSeen: first}
	}

	// Audience binding.
	if audience != "" {
		if payload.Aud != "" && payload.Aud != "*" && payload.Aud != audience {
			return failure(
				types.ErrAudienceMismatch,
				fmt.Sprintf("Credential audience '%s' does not match verifier '%s'", payload.Aud, audience),
			)
		}
	}

	return result
}

// VerifyCredentialWithResolver decodes the credential to extract the issuer
// domain, uses r to resolve discovery + revocation, and runs
// VerifyCredentialOffline.
func VerifyCredentialWithResolver(
	credentialJWT string,
	r resolver.DiscoveryResolver,
	pinStore *pinning.KeyPinStore,
	audience string,
	config VerifierConfig,
) Result {
	_, payload, _, err := jwt.DecodeJWTUnverified(credentialJWT)
	if err != nil {
		return failure(types.ErrAlgorithmRejected, fmt.Sprintf("JWT parse failed: %v", err))
	}

	disc, err := r.ResolveDiscovery(payload.Iss)
	if err != nil {
		return failure(types.ErrDiscoveryFetchFailed, fmt.Sprintf("Failed to resolve discovery document: %v", err))
	}

	rev, err := r.ResolveRevocation(payload.Iss, disc)
	if err != nil {
		return failure(types.ErrDiscoveryFetchFailed, "Revocation document unreachable (fail-closed)")
	}

	return VerifyCredentialOffline(credentialJWT, disc, rev, pinStore, audience, config)
}
