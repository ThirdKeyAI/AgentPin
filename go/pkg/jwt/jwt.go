// Package jwt implements ES256-only JWT encoding, decoding, and verification
// for AgentPin credentials.
//
// SECURITY: This package is intentionally NOT a general-purpose JWT library.
// It rejects every algorithm except ES256 and every type except
// "agentpin-credential+jwt" up front, before any signature work happens. It
// uses Go stdlib crypto/ecdsa directly so there is no third-party JWT
// dependency with permissive `alg` defaults.
//
// Wire compatibility: signatures are DER-encoded ECDSA bytes, base64url-no-pad
// encoded. This matches the Rust SDK (signature.to_der().as_bytes()), the
// JavaScript SDK, and the Python SDK — it differs from RFC 7515 ES256, which
// would use raw r||s. AgentPin spec uses DER for cross-language uniformity
// across native ECDSA libraries. Do not change this without coordinating
// every SDK simultaneously.
package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

const (
	// RequiredAlg is the only signature algorithm AgentPin accepts.
	RequiredAlg = "ES256"
	// RequiredTyp is the only token type AgentPin credentials may carry.
	RequiredTyp = "agentpin-credential+jwt"
)

// Base64URLEncode encodes data with the unpadded base64url alphabet.
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes an unpadded base64url string.
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// EncodeJWT serializes header + payload, signs the "<header>.<payload>"
// signing input with priv, and returns the compact JWT string. The header's
// alg/typ fields are NOT overridden — the caller is responsible for setting
// them to ES256 / agentpin-credential+jwt; the verifier will reject anything
// else.
func EncodeJWT(header *types.JWTHeader, payload *types.JWTPayload, priv *ecdsa.PrivateKey) (string, error) {
	hb, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	signingInput := Base64URLEncode(hb) + "." + Base64URLEncode(pb)

	sigB64, err := crypto.SignBytes(priv, []byte(signingInput))
	if err != nil {
		return "", err
	}
	// crypto.SignBytes uses standard base64; convert raw DER to base64url.
	derSig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", fmt.Errorf("internal: re-decode signature: %w", err)
	}
	return signingInput + "." + Base64URLEncode(derSig), nil
}

// DecodeJWTUnverified parses and validates only the JWT shape, alg, and typ.
// It does NOT verify the signature — callers must call VerifyJWT for that.
//
// Returns the parsed header, payload, and the raw base64url signature
// segment. Rejects anything other than ES256 / agentpin-credential+jwt with
// a descriptive error.
func DecodeJWTUnverified(jwt string) (*types.JWTHeader, *types.JWTPayload, string, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, nil, "", errors.New("JWT must have 3 parts")
	}

	hb, err := Base64URLDecode(parts[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode header: %w", err)
	}
	pb, err := Base64URLDecode(parts[1])
	if err != nil {
		return nil, nil, "", fmt.Errorf("decode payload: %w", err)
	}

	var header types.JWTHeader
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, nil, "", fmt.Errorf("invalid JWT header: %w", err)
	}
	var payload types.JWTPayload
	if err := json.Unmarshal(pb, &payload); err != nil {
		return nil, nil, "", fmt.Errorf("invalid JWT payload: %w", err)
	}

	// SECURITY: reject any algorithm except ES256 BEFORE verifying.
	if header.Alg != RequiredAlg {
		return nil, nil, "", fmt.Errorf("algorithm '%s' rejected, must be '%s'", header.Alg, RequiredAlg)
	}
	if header.Typ != RequiredTyp {
		return nil, nil, "", fmt.Errorf("token type '%s' rejected, must be '%s'", header.Typ, RequiredTyp)
	}

	return &header, &payload, parts[2], nil
}

// VerifyJWT verifies a JWT signature with pub. Returns the decoded header
// and payload on success.
func VerifyJWT(jwt string, pub *ecdsa.PublicKey) (*types.JWTHeader, *types.JWTPayload, error) {
	header, payload, sigB64URL, err := DecodeJWTUnverified(jwt)
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(jwt, ".")
	signingInput := parts[0] + "." + parts[1]

	sig, err := Base64URLDecode(sigB64URL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	// Convert DER bytes back to standard base64 for crypto.VerifyBytes.
	stdSig := base64.StdEncoding.EncodeToString(sig)
	ok, err := crypto.VerifyBytes(pub, []byte(signingInput), stdSig)
	if err != nil {
		return nil, nil, fmt.Errorf("verify signature: %w", err)
	}
	if !ok {
		return nil, nil, errors.New("signature verification failed")
	}
	return header, payload, nil
}
