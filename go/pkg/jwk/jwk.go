// Package jwk converts ECDSA P-256 keys to/from AgentPin JWK and computes
// RFC 7638 JWK thumbprints byte-identically to the Rust SDK.
package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// VerifyingKeyToJWK converts a P-256 public key into the AgentPin JWK form.
//
// The "use" field is fixed to "sig" and key_ops to ["verify"], matching the
// Rust port verbatim so wire format stays compatible.
func VerifyingKeyToJWK(pub *ecdsa.PublicKey, kid string) types.JWK {
	x := padTo32(pub.X.Bytes())
	y := padTo32(pub.Y.Bytes())
	return types.JWK{
		Kid:    kid,
		Kty:    "EC",
		Crv:    "P-256",
		X:      base64.RawURLEncoding.EncodeToString(x),
		Y:      base64.RawURLEncoding.EncodeToString(y),
		Use:    "sig",
		KeyOps: []string{"verify"},
	}
}

// JWKToVerifyingKey converts an AgentPin JWK back into a P-256 public key.
func JWKToVerifyingKey(j *types.JWK) (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, errors.New("invalid key format: kty/crv not EC/P-256")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("invalid key format: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid key format: %w", err)
	}
	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, errors.New("invalid key format: x/y must be 32 bytes")
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("invalid key format: point not on P-256")
	}
	return pub, nil
}

// PEMToJWK converts a PEM SPKI public key to a JWK with the given kid.
func PEMToJWK(pubPEM, kid string) (types.JWK, error) {
	pub, err := crypto.LoadPublicKey(pubPEM)
	if err != nil {
		return types.JWK{}, err
	}
	return VerifyingKeyToJWK(pub, kid), nil
}

// JWKToPEM converts a JWK to PEM SPKI form.
func JWKToPEM(j *types.JWK) (string, error) {
	pub, err := JWKToVerifyingKey(j)
	if err != nil {
		return "", err
	}
	return crypto.MarshalPublicKeyPEM(pub)
}

// JWKThumbprint computes the RFC 7638 JWK thumbprint:
// SHA-256 of {"crv":"P-256","kty":"EC","x":"<x>","y":"<y>"} (sorted keys, no
// whitespace), hex-encoded. Wire format must match the Rust port byte-for-byte.
func JWKThumbprint(j *types.JWK) string {
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, j.Crv, j.Kty, j.X, j.Y)
	return crypto.SHA256Hex([]byte(canonical))
}

// padTo32 left-pads a big-endian byte slice to length 32 with zeros, as
// required by JWK encoding for P-256 coordinates.
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
