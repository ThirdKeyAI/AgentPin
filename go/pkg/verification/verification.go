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
	"errors"
	"fmt"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/delegation"
	"github.com/ThirdKeyAi/agentpin/go/pkg/discovery"
	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
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
	// RequireSignedRevocation rejects unsigned revocation documents (default
	// false). Signed documents are always verified when a signature is
	// present.
	RequireSignedRevocation bool
	// RevocationMaxAgeSecs, when > 0, rejects a revocation document whose
	// updated_at is older than this many seconds or unparsable.
	RevocationMaxAgeSecs int64
	// AllowUnverifiedDelegation accepts a credential whose delegation_chain
	// could not be verified (no resolver for the attesters' documents),
	// reporting delegation_verified=false plus a warning. By default such a
	// credential is rejected with DELEGATION_INVALID (spec §6.1 step 10;
	// AP-2, design issue 10).
	AllowUnverifiedDelegation bool
}

// DefaultVerifierConfig returns the default verifier configuration.
func DefaultVerifierConfig() VerifierConfig {
	return VerifierConfig{
		ClockSkewSecs:      60,
		MaxTTLSecs:         86400,
		StrictCapabilities: false,
	}
}

// DefaultCredentialTTLMax is the credential_ttl_max assumed when an agent
// declaration omits it (spec §4.5).
const DefaultCredentialTTLMax uint64 = 86400

// CheckKeyUsable rejects keys that are expired, not marked for signature
// use, or whose key_ops exclude "verify" (spec §4.4; AP-20, AP-21). An
// unparsable exp is a failure, not a pass.
func CheckKeyUsable(kk *types.JWK, now, skew int64) error {
	if kk.Exp != "" {
		expDt, err := time.Parse(time.RFC3339, kk.Exp)
		if err != nil {
			return types.NewVerificationError(types.ErrKeyExpired, fmt.Sprintf("Key '%s' has an unparsable exp '%s'", kk.Kid, kk.Exp))
		}
		if expDt.Unix() < now-skew {
			return types.NewVerificationError(types.ErrKeyExpired, fmt.Sprintf("Key '%s' has expired", kk.Kid))
		}
	}
	if kk.Use != "sig" {
		return types.NewVerificationError(types.ErrKeyNotFound, fmt.Sprintf("Key '%s' is not a signature key (use = '%s')", kk.Kid, kk.Use))
	}
	if kk.KeyOps != nil {
		ok := false
		for _, op := range kk.KeyOps {
			if op == "verify" {
				ok = true
				break
			}
		}
		if !ok {
			return types.NewVerificationError(types.ErrKeyNotFound, fmt.Sprintf("Key '%s' key_ops do not permit verify", kk.Kid))
		}
	}
	return nil
}

func verificationFailure(err error, fallback types.ErrorCode) Result {
	if ve, ok := types.AsVerificationError(err); ok {
		return failure(ve.Code, ve.Message)
	}
	return failure(fallback, err.Error())
}

// verifyDelegationChain implements spec §6.4: every attestation is verified
// against its attester's discovery document, Maker/Deployer scope narrowing
// is checked, and the minimum max_delegation_depth across all participants
// is enforced.
func verifyDelegationChain(
	chain []types.DelegationAttestation,
	issuer string,
	payload *types.JWTPayload,
	disc *types.DiscoveryDocument,
	r resolver.DiscoveryResolver,
	now, skew int64,
) ([]DelegationChainEntry, *Result) {
	fail := func(msg string) *Result {
		res := failure(types.ErrDelegationInvalid, msg)
		return &res
	}
	depths := []uint8{disc.MaxDelegationDepth}
	entries := make([]DelegationChainEntry, 0, len(chain))
	for _, att := range chain {
		domainName, err := domain.Normalize(att.Domain)
		if err != nil {
			return nil, fail(fmt.Sprintf("Delegation attester domain invalid: %v", err))
		}
		doc, err := r.ResolveDiscovery(domainName)
		if err != nil {
			return nil, fail(fmt.Sprintf("Cannot resolve discovery document for delegation attester '%s': %v", domainName, err))
		}
		if err := discovery.ValidateDiscoveryDocument(doc, domainName); err != nil {
			return nil, fail(fmt.Sprintf("Discovery document for delegation attester '%s' invalid: %v", domainName, err))
		}
		kk := discovery.FindKeyByKid(doc, att.Kid)
		if kk == nil {
			return nil, fail(fmt.Sprintf("Delegation attester '%s' has no key '%s'", domainName, att.Kid))
		}
		if err := CheckKeyUsable(kk, now, skew); err != nil {
			return nil, fail(fmt.Sprintf("Delegation attester '%s' key '%s' unusable: %v", domainName, att.Kid, err))
		}
		pub, err := jwk.JWKToVerifyingKey(kk)
		if err != nil {
			return nil, fail(fmt.Sprintf("Delegation attester '%s' key '%s' invalid: %v", domainName, att.Kid, err))
		}
		a := att
		if err := delegation.VerifyAttestation(&a, pub, issuer, payload.Sub, payload.Capabilities); err != nil {
			return nil, fail(err.Error())
		}
		// Scope narrowing (spec §10.3): when the attester declares the
		// attested agent, it must be active and the credential capabilities
		// must be within what the attester declared for it.
		if agent := discovery.FindAgentByID(doc, att.AgentID); agent != nil {
			if agent.Status != types.AgentActive {
				return nil, fail(fmt.Sprintf("Delegation attester '%s' declares agent '%s' as %s", domainName, att.AgentID, agent.Status))
			}
			if !types.CapabilitiesSubset(agent.Capabilities, payload.Capabilities) {
				return nil, fail(fmt.Sprintf("Credential capabilities exceed those declared by delegation attester '%s' for '%s'", domainName, att.AgentID))
			}
		}
		depths = append(depths, doc.MaxDelegationDepth)
		entries = append(entries, DelegationChainEntry{Domain: domainName, Role: string(att.Role), Verified: true})
	}
	if err := delegation.VerifyChainDepth(len(chain), depths); err != nil {
		res := verificationFailure(err, types.ErrDelegationDepthExceeded)
		return nil, &res
	}
	return entries, nil
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

// parseFailure maps a decode error: claim-shape problems are
// MALFORMED_CREDENTIAL, everything else (structure, alg, typ) is
// ALGORITHM_REJECTED.
func parseFailure(err error) Result {
	var mce *jwt.MalformedCredentialError
	if errors.As(err, &mce) {
		return failure(types.ErrMalformedCredential, mce.Reason)
	}
	return failure(types.ErrAlgorithmRejected, fmt.Sprintf("JWT parse failed: %v", err))
}

// VerifyCredentialOffline runs the full 12-step verification flow against a
// caller-provided discovery (and optional revocation) document.
//
// Without a resolver for the attesters' discovery documents a
// delegation_chain cannot be verified; by default such a credential is
// rejected. Use VerifyCredentialOfflineWithChain to supply the attesters'
// documents (for example from a TrustBundleResolver).
func VerifyCredentialOffline(
	credentialJWT string,
	disc *types.DiscoveryDocument,
	rev *types.RevocationDocument,
	pinStore *pinning.KeyPinStore,
	audience string,
	config VerifierConfig,
) Result {
	return verifyCredentialCore(credentialJWT, disc, rev, pinStore, audience, config, nil)
}

// VerifyCredentialOfflineWithChain is VerifyCredentialOffline with a
// resolver used only to fetch the discovery documents of delegation-chain
// attesters.
func VerifyCredentialOfflineWithChain(
	credentialJWT string,
	disc *types.DiscoveryDocument,
	rev *types.RevocationDocument,
	pinStore *pinning.KeyPinStore,
	audience string,
	config VerifierConfig,
	chain resolver.DiscoveryResolver,
) Result {
	return verifyCredentialCore(credentialJWT, disc, rev, pinStore, audience, config, chain)
}

func verifyCredentialCore(
	credentialJWT string,
	disc *types.DiscoveryDocument,
	rev *types.RevocationDocument,
	pinStore *pinning.KeyPinStore,
	audience string,
	config VerifierConfig,
	chain resolver.DiscoveryResolver,
) Result {
	// Steps 1-2: Parse JWT (alg/typ enforced inside DecodeJWTUnverified, then
	// claim shape — AP-5 / AP-18).
	header, payload, _, err := jwt.DecodeJWTUnverified(credentialJWT)
	if err != nil {
		return parseFailure(err)
	}

	// Normalize the issuer domain before it is used as a lookup key anywhere
	// (pin store, entity comparison, resolver paths/URLs) — AP-3.
	issuer, err := domain.Normalize(payload.Iss)
	if err != nil {
		return failure(types.ErrDiscoveryInvalid, fmt.Sprintf("Invalid issuer domain: %v", err))
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
	// Claims were validated non-negative with exp > iat, so this cannot wrap
	// (AP-14).
	lifetime := payload.Exp - payload.Iat
	if lifetime <= 0 {
		return failure(types.ErrMalformedCredential, "exp must be greater than iat")
	}
	if lifetime > config.MaxTTLSecs {
		return failure(
			types.ErrCredentialExpired,
			fmt.Sprintf("Credential lifetime %d exceeds max TTL %d", lifetime, config.MaxTTLSecs),
		)
	}

	// Steps 5-6: Validate discovery document (entity matches iss).
	if err := discovery.ValidateDiscoveryDocument(disc, issuer); err != nil {
		return failure(types.ErrDiscoveryInvalid, fmt.Sprintf("Discovery validation failed: %v", err))
	}

	// Step 7: Resolve public key by kid.
	kk := discovery.FindKeyByKid(disc, header.Kid)
	if kk == nil {
		return failure(types.ErrKeyNotFound, fmt.Sprintf("Key '%s' not found in discovery document", header.Kid))
	}
	// Key expiration and usage (an unparsable exp is a failure, not a pass —
	// AP-20; use/key_ops enforced — AP-21).
	if err := CheckKeyUsable(kk, now, skew); err != nil {
		return verificationFailure(err, types.ErrKeyNotFound)
	}
	pub, err := jwk.JWKToVerifyingKey(kk)
	if err != nil {
		return failure(types.ErrKeyNotFound, fmt.Sprintf("Invalid key format for '%s': %v", header.Kid, err))
	}

	// Step 3: Verify JWT signature.
	if _, _, err := jwt.VerifyJWT(credentialJWT, pub); err != nil {
		return failure(types.ErrSignatureInvalid, fmt.Sprintf("JWT signature verification failed for kid '%s'", header.Kid))
	}

	// Step 10: Revocation. The document must belong to this issuer and, when
	// signed, verify under a discovery key (design issue 3).
	if rev != nil {
		if err := revocation.VerifyRevocationDocument(rev, disc); err != nil {
			return failure(types.ErrDiscoveryInvalid, fmt.Sprintf("Revocation document invalid: %v", err))
		}
		if config.RequireSignedRevocation && rev.Signature == "" {
			return failure(types.ErrDiscoveryInvalid, "Revocation document is not signed")
		}
		if config.RevocationMaxAgeSecs > 0 {
			if err := revocation.CheckRevocationFreshness(rev, config.RevocationMaxAgeSecs); err != nil {
				return failure(types.ErrDiscoveryInvalid, fmt.Sprintf("Revocation document invalid: %v", err))
			}
		}
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

	// Spec §5.7: exp - iat MUST NOT exceed the agent's credential_ttl_max
	// (default 86400 when omitted) — AP-14.
	ttlMax := DefaultCredentialTTLMax
	if agent.CredentialTTLMax != nil {
		ttlMax = *agent.CredentialTTLMax
	}
	if uint64(lifetime) > ttlMax {
		return failure(
			types.ErrCredentialExpired,
			fmt.Sprintf("Credential lifetime %d exceeds agent credential_ttl_max %d", lifetime, ttlMax),
		)
	}

	// Step 11: Capability subset.
	if err := credential.ValidateCredentialAgainstDiscovery(payload.Capabilities, agent.Capabilities); err != nil {
		return failure(types.ErrCapabilityExceeded, err.Error())
	}

	// Constraints: validate and compute the effective (merged) set the
	// consumer must enforce — discovery defaults narrowed by the credential
	// (AP-15).
	effectiveConstraints, err := types.MergeConstraints(agent.Constraints, payload.Constraints)
	if err != nil {
		return failure(types.ErrConstraintViolation,
			fmt.Sprintf("Credential constraints are less restrictive than discovery defaults: %v", err))
	}

	// Build success result; pinning + delegation populated below.
	result := Result{
		Valid:        true,
		AgentID:      payload.Sub,
		Issuer:       issuer,
		Capabilities: payload.Capabilities,
		Constraints:  effectiveConstraints,
		Warnings:     []string{},
	}

	// Step 12: Delegation chain. Every attestation is verified against its
	// attester's discovery document (spec §6.4); a chain that cannot be
	// verified fails closed unless the verifier opted out (AP-2).
	if len(payload.DelegationChain) > 0 {
		switch {
		case chain != nil:
			entries, failed := verifyDelegationChain(payload.DelegationChain, issuer, payload, disc, chain, now, skew)
			if failed != nil {
				return *failed
			}
			result.DelegationChain = entries
			tr := true
			result.DelegationVerified = &tr
		case !config.AllowUnverifiedDelegation:
			return failure(types.ErrDelegationInvalid, "Delegation chain present but no resolver is available to verify it")
		default:
			entries := make([]DelegationChainEntry, 0, len(payload.DelegationChain))
			for _, att := range payload.DelegationChain {
				entries = append(entries, DelegationChainEntry{Domain: att.Domain, Role: string(att.Role), Verified: false})
			}
			result.DelegationChain = entries
			f := false
			result.DelegationVerified = &f
			result.Warnings = append(result.Warnings, "Delegation chain present but not verified (AllowUnverifiedDelegation is set)")
		}
	}

	// Step 8: TOFU key pinning.
	pr, perr := pinning.CheckPinning(pinStore, issuer, kk)
	if perr != nil {
		return failure(types.ErrKeyPinMismatch, fmt.Sprintf("Key for '%s' has changed since last pinned", issuer))
	}
	switch pr {
	case pinning.ResultFirstUse:
		result.KeyPinning = &KeyPinningStatus{
			Status:    "first_use",
			FirstSeen: time.Now().UTC().Format(time.RFC3339),
		}
	case pinning.ResultMatched:
		var first string
		if pd := pinStore.GetDomain(issuer); pd != nil && len(pd.PinnedKeys) > 0 {
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
		return parseFailure(err)
	}

	issuer, err := domain.Normalize(payload.Iss)
	if err != nil {
		return failure(types.ErrDiscoveryInvalid, fmt.Sprintf("Invalid issuer domain: %v", err))
	}

	disc, err := r.ResolveDiscovery(issuer)
	if err != nil {
		return failure(types.ErrDiscoveryFetchFailed, fmt.Sprintf("Failed to resolve discovery document: %v", err))
	}

	rev, err := r.ResolveRevocation(issuer, disc)
	if err != nil {
		return failure(types.ErrDiscoveryFetchFailed, "Revocation document unreachable (fail-closed)")
	}

	return verifyCredentialCore(credentialJWT, disc, rev, pinStore, audience, config, r)
}
