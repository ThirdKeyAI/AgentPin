// Package mutual implements the AgentPin challenge / response mutual-auth
// flow with 128-bit random nonces (spec §9).
//
// The responder signs a domain-separated structure, never the raw nonce:
//
//	"agentpin-response-v1" 0x00 len(nonce) nonce len(timestamp) timestamp
//	                            len(kid) kid len(binding) binding
//
// where binding is the SHA-256 (hex) of the challenge's verifier_credential
// when present (empty otherwise). This binds a response to this verifier
// and this challenge only, and keeps the signature disjoint from credential,
// attestation and AgentCard signatures (AP-1, design issue 8).
//
// Nonces are single-use by default: verification always goes through a
// nonce store (a package-wide InMemoryStore unless the caller supplies one)
// and the nonce is recorded only after the signature verified, so a forged
// response cannot burn a legitimate nonce (AP-19).
package mutual

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/nonce"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

const (
	// NonceExpirySecs is the challenge validity window (spec §9.2).
	NonceExpirySecs = int64(60)
	// NonceBytes is the nonce length in bytes (128 bits).
	NonceBytes = 16
	// NonceEncodedLen is the length of an unpadded base64url nonce.
	NonceEncodedLen = 22
	// ChallengeType is the wire "type" of a challenge.
	ChallengeType = "agentpin-challenge"
	// ResponseType is the wire "type" of a response.
	ResponseType = "agentpin-response"
)

var defaultStore = nonce.NewInMemoryStore()

// CreateChallenge produces a fresh challenge with a 128-bit random nonce.
// verifierCredential may be empty to omit the field.
func CreateChallenge(verifierCredential string) (*types.Challenge, error) {
	var n [NonceBytes]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, fmt.Errorf("read random nonce: %w", err)
	}
	return &types.Challenge{
		Type:               ChallengeType,
		Nonce:              base64.RawURLEncoding.EncodeToString(n[:]),
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		VerifierCredential: verifierCredential,
	}, nil
}

// ValidateNonce checks that n is exactly 22 canonical base64url characters
// decoding to 16 bytes, so a responder is never asked to sign caller-shaped
// bytes.
func ValidateNonce(n string) error {
	if len(n) != NonceEncodedLen {
		return fmt.Errorf("challenge nonce must be %d base64url characters", NonceEncodedLen)
	}
	raw, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return errors.New("challenge nonce is not valid base64url")
	}
	if len(raw) != NonceBytes || base64.RawURLEncoding.EncodeToString(raw) != n {
		return fmt.Errorf("challenge nonce must decode to exactly %d bytes", NonceBytes)
	}
	return nil
}

// VerifierBinding returns the SHA-256 hex of the challenge's verifier
// credential, or "" when absent.
func VerifierBinding(c *types.Challenge) string {
	if c.VerifierCredential == "" {
		return ""
	}
	return crypto.SHA256Hex([]byte(c.VerifierCredential))
}

// ResponseSigningInput returns the bytes a responder with key kid commits
// to for challenge c.
func ResponseSigningInput(c *types.Challenge, kid string) []byte {
	return crypto.DomainSeparatedInput(
		crypto.CtxResponse,
		[]byte(c.Nonce),
		[]byte(c.Timestamp),
		[]byte(kid),
		[]byte(VerifierBinding(c)),
	)
}

// CreateResponse signs the domain-separated challenge structure with priv.
// Returns an error for a malformed nonce or wrong challenge type.
func CreateResponse(challenge *types.Challenge, priv *ecdsa.PrivateKey, kid string) (*types.Response, error) {
	if challenge.Type != ChallengeType {
		return nil, fmt.Errorf("challenge type '%s' rejected, must be '%s'", challenge.Type, ChallengeType)
	}
	if err := ValidateNonce(challenge.Nonce); err != nil {
		return nil, err
	}
	sig, err := crypto.SignBytes(priv, ResponseSigningInput(challenge, kid))
	if err != nil {
		return nil, err
	}
	return &types.Response{
		Type:      ResponseType,
		Nonce:     challenge.Nonce,
		Signature: sig,
		Kid:       kid,
	}, nil
}

// VerifyResponse checks the response using the package-wide nonce store, so
// each nonce is accepted at most once per process.
func VerifyResponse(response *types.Response, challenge *types.Challenge, pub *ecdsa.PublicKey) (bool, error) {
	return VerifyResponseWithStore(response, challenge, pub, nil)
}

// VerifyResponseWithStore checks the response: nonce/type shape, challenge
// freshness, signature, then single-use recording in store (the package-wide
// store when nil). Returns false (no error) when the nonce does not match or
// the signature does not verify; returns an error for malformed input,
// expired challenges and replayed nonces.
func VerifyResponseWithStore(response *types.Response, challenge *types.Challenge, pub *ecdsa.PublicKey, store nonce.Store) (bool, error) {
	if response.Type != ResponseType || challenge.Type != ChallengeType {
		return false, nil
	}
	if response.Nonce != challenge.Nonce {
		return false, nil
	}
	if err := ValidateNonce(challenge.Nonce); err != nil {
		return false, err
	}

	// An unparsable timestamp is treated as expired (fail closed).
	ts, err := time.Parse(time.RFC3339, challenge.Timestamp)
	if err != nil {
		return false, errors.New("challenge timestamp is not valid RFC 3339")
	}
	elapsed := time.Now().Unix() - ts.Unix()
	if elapsed > NonceExpirySecs {
		return false, fmt.Errorf("challenge nonce expired (%d seconds old, max %d)", elapsed, NonceExpirySecs)
	}

	// Verify the signature before touching the nonce store so a forged
	// response cannot consume a legitimate nonce.
	ok, err := crypto.VerifyBytes(pub, ResponseSigningInput(challenge, response.Kid), response.Signature)
	if err != nil || !ok {
		return false, err
	}

	if store == nil {
		store = defaultStore
	}
	fresh, err := store.CheckAndRecord(response.Nonce, time.Duration(NonceExpirySecs)*time.Second)
	if err != nil {
		return false, err
	}
	if !fresh {
		return false, errors.New("nonce has already been used")
	}
	return true, nil
}
