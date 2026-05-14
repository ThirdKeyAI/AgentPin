// Package crypto provides ECDSA P-256 key generation and DER-signature
// helpers used by the AgentPin Go SDK. Wire format and key encoding match
// the Rust, JavaScript, and Python ports.
package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

// KeyPair holds a generated ECDSA P-256 key pair in PEM (PKCS#8 / SPKI) form.
type KeyPair struct {
	PrivateKeyPEM string
	PublicKeyPEM  string
}

// GenerateKeyPair generates a new ECDSA P-256 key pair and returns it as PEM
// (PKCS#8 private + SPKI public).
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa generate: %w", err)
	}
	privPEM, err := MarshalPrivateKeyPEM(priv)
	if err != nil {
		return nil, err
	}
	pubPEM, err := MarshalPublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KeyPair{PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM}, nil
}

// MarshalPrivateKeyPEM serializes an ECDSA P-256 private key as PKCS#8 PEM
// using LF line endings to match the Rust SDK.
func MarshalPrivateKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal pkcs8: %w", err)
	}
	return encodePEM("PRIVATE KEY", der), nil
}

// MarshalPublicKeyPEM serializes an ECDSA P-256 public key as SPKI PEM with
// LF line endings.
func MarshalPublicKeyPEM(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal spki: %w", err)
	}
	return encodePEM("PUBLIC KEY", der), nil
}

// encodePEM writes a PEM block with LF line endings to match the Rust port's
// EncodeMemoryLF behaviour.
func encodePEM(blockType string, der []byte) string {
	const lineLen = 64
	b64 := base64.StdEncoding.EncodeToString(der)
	out := "-----BEGIN " + blockType + "-----\n"
	for i := 0; i < len(b64); i += lineLen {
		end := i + lineLen
		if end > len(b64) {
			end = len(b64)
		}
		out += b64[i:end] + "\n"
	}
	out += "-----END " + blockType + "-----\n"
	return out
}

// LoadPrivateKey parses a PEM-encoded ECDSA P-256 private key (PKCS#8 or
// SEC1 EC).
func LoadPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an ECDSA private key")
		}
		return ec, nil
	}
	ec, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return ec, nil
}

// LoadPublicKey parses a PEM-encoded ECDSA P-256 public key (SPKI).
func LoadPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	if ec.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	return ec, nil
}

// SignBytes signs raw bytes with priv and returns the DER-encoded signature
// base64-encoded (standard, padded — matches the Rust `sign_data`/`sign_bytes`
// helpers).
func SignBytes(priv *ecdsa.PrivateKey, data []byte) (string, error) {
	der, err := ecdsa.SignASN1(rand.Reader, priv, hash(data))
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// VerifyBytes verifies a base64-standard-encoded DER signature against data.
func VerifyBytes(pub *ecdsa.PublicKey, data []byte, sigB64 string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ecdsa.VerifyASN1(pub, hash(data), sig), nil
}

// SignData signs data with a PEM-encoded private key. Returns base64-encoded
// DER signature.
func SignData(privPEM string, data []byte) (string, error) {
	priv, err := LoadPrivateKey(privPEM)
	if err != nil {
		return "", err
	}
	return SignBytes(priv, data)
}

// VerifySignature verifies a base64-standard signature against data using a
// PEM-encoded public key.
func VerifySignature(pubPEM string, data []byte, sigB64 string) (bool, error) {
	pub, err := LoadPublicKey(pubPEM)
	if err != nil {
		return false, err
	}
	return VerifyBytes(pub, data, sigB64)
}

// GenerateKeyID returns the SHA-256 hex digest of the SPKI DER bytes of a
// PEM-encoded public key. Matches the Rust `generate_key_id` output.
func GenerateKeyID(pubPEM string) (string, error) {
	pub, err := LoadPublicKey(pubPEM)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// SHA256Hex returns the SHA-256 hex digest of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hash returns the SHA-256 digest of data; used as the message hash for
// ECDSA-P256 signing per the AgentPin spec (ES256).
func hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}
