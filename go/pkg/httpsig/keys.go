package httpsig

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
)

const (
	// AlgEd25519 is the RFC 9421 alg value for Ed25519.
	AlgEd25519 = "ed25519"
	// AlgRSAPSSSHA512 is the RFC 9421 alg value for RSASSA-PSS with SHA-512.
	AlgRSAPSSSHA512 = "rsa-pss-sha512"

	minRSABits = 2048
	maxRSABits = 8192
	// maxRSASigningBits matches the Rust crate, which signs with keys up to 4096 bits.
	maxRSASigningBits = 4096
	pssSaltLen        = 64
)

var (
	// ErrSignatureInvalid is returned when a signature does not verify.
	ErrSignatureInvalid = errors.New("signature invalid")
	// ErrInvalidKeyFormat is returned for unusable or malformed keys.
	ErrInvalidKeyFormat = errors.New("invalid key format")
)

// PublicKey verifies HTTP message signatures. Exactly one field is set.
type PublicKey struct {
	Ed25519 ed25519.PublicKey
	RSA     *rsa.PublicKey
}

// Ed25519PublicKey wraps an Ed25519 public key.
func Ed25519PublicKey(k ed25519.PublicKey) PublicKey { return PublicKey{Ed25519: k} }

// Alg is the RFC 9421 alg this key verifies.
func (k PublicKey) Alg() string {
	if k.RSA != nil {
		return AlgRSAPSSSHA512
	}
	return AlgEd25519
}

// Equal reports whether two keys are the same.
func (k PublicKey) Equal(o PublicKey) bool {
	if k.RSA != nil || o.RSA != nil {
		return k.RSA != nil && o.RSA != nil && k.RSA.Equal(o.RSA)
	}
	return bytes.Equal(k.Ed25519, o.Ed25519)
}

// IsZero reports whether no key is set.
func (k PublicKey) IsZero() bool { return k.RSA == nil && len(k.Ed25519) == 0 }

// Verify checks sig over data. Ed25519 verification is strict: small-order
// public keys and R values are rejected, as are non-canonical encodings. RSA
// keys must be 2048 to 8192 bits; the PSS salt is 64 bytes.
func (k PublicKey) Verify(data, sig []byte) error {
	if k.RSA != nil {
		bits := k.RSA.N.BitLen()
		e := k.RSA.E
		if bits < minRSABits || bits > maxRSABits || e < 3 || e&1 == 0 {
			return ErrSignatureInvalid
		}
		h := sha512.Sum512(data)
		if rsa.VerifyPSS(k.RSA, crypto.SHA512, h[:], sig, &rsa.PSSOptions{SaltLength: pssSaltLen}) != nil {
			return ErrSignatureInvalid
		}
		return nil
	}
	if len(k.Ed25519) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrSignatureInvalid
	}
	if smallOrder(k.Ed25519) || smallOrder(sig[:32]) {
		return ErrSignatureInvalid
	}
	if !ed25519.Verify(k.Ed25519, data, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// PrivateKey signs HTTP messages. Exactly one field is set.
type PrivateKey struct {
	Ed25519 ed25519.PrivateKey
	RSA     *rsa.PrivateKey
}

// Ed25519PrivateKey wraps an Ed25519 private key.
func Ed25519PrivateKey(k ed25519.PrivateKey) PrivateKey { return PrivateKey{Ed25519: k} }

// PublicKey returns the matching public key.
func (k PrivateKey) PublicKey() PublicKey {
	if k.RSA != nil {
		return PublicKey{RSA: &k.RSA.PublicKey}
	}
	return PublicKey{Ed25519: k.Ed25519.Public().(ed25519.PublicKey)}
}

// Alg is the RFC 9421 alg this key signs with.
func (k PrivateKey) Alg() string { return k.PublicKey().Alg() }

// Sign signs data.
func (k PrivateKey) Sign(data []byte) ([]byte, error) {
	if k.RSA != nil {
		h := sha512.Sum512(data)
		sig, err := rsa.SignPSS(rand.Reader, k.RSA, crypto.SHA512, h[:], &rsa.PSSOptions{SaltLength: pssSaltLen})
		if err != nil {
			return nil, errorf("RSA signing failed")
		}
		return sig, nil
	}
	if len(k.Ed25519) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKeyFormat
	}
	return ed25519.Sign(k.Ed25519, data), nil
}

// LoadPrivateKeyPEM loads a PEM key: PKCS#8 ("PRIVATE KEY") Ed25519 or
// RSA, or PKCS#1 ("RSA PRIVATE KEY"). RSA signing keys must be 2048 to 4096 bits.
func LoadPrivateKeyPEM(pemStr string) (PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return PrivateKey{}, ErrInvalidKeyFormat
	}
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return PrivateKey{}, ErrInvalidKeyFormat
	}
	if err != nil {
		return PrivateKey{}, ErrInvalidKeyFormat
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return PrivateKey{Ed25519: k}, nil
	case *rsa.PrivateKey:
		if n := (k.N.BitLen() + 7) / 8; n < minRSABits/8 || n > maxRSASigningBits/8 {
			return PrivateKey{}, ErrInvalidKeyFormat
		}
		return PrivateKey{RSA: k}, nil
	}
	return PrivateKey{}, ErrInvalidKeyFormat
}

// MarshalPrivateKeyPEM encodes a key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(k PrivateKey) (string, error) {
	var key any = k.Ed25519
	if k.RSA != nil {
		key = k.RSA
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// ---------------------------------------------------------------------------
// Ed25519 point checks
// ---------------------------------------------------------------------------

var (
	fieldP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// d = -121665/121666 mod p
	edD = func() *big.Int {
		d := new(big.Int).ModInverse(big.NewInt(121666), fieldP)
		d.Mul(d, big.NewInt(-121665))
		return d.Mod(d, fieldP)
	}()
)

// edY decodes the y coordinate (reduced mod p) of an encoded point.
func edY(enc []byte) *big.Int {
	le := make([]byte, 32)
	copy(le, enc)
	le[31] &= 0x7f
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	y := new(big.Int).SetBytes(le)
	return y.Mod(y, fieldP)
}

// ValidEd25519Point reports whether enc decodes to a curve point.
func ValidEd25519Point(enc []byte) bool {
	if len(enc) != 32 {
		return false
	}
	y := edY(enc)
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(edD, y2)
	den.Add(den, big.NewInt(1)).Mod(den, fieldP)
	inv := new(big.Int).ModInverse(den, fieldP)
	if inv == nil {
		return false
	}
	x2 := num.Mul(num, inv)
	x2.Mod(x2, fieldP)
	return big.Jacobi(x2, fieldP) != -1
}

// smallOrder reports whether an encoded Edwards point has small order (or
// does not decode). It maps the point to its Montgomery u-coordinate and
// runs X25519 with a clamped scalar, which yields zero exactly for
// small-order points.
func smallOrder(enc []byte) bool {
	if !ValidEd25519Point(enc) {
		return true
	}
	y := edY(enc)
	den := new(big.Int).Sub(big.NewInt(1), y)
	den.Mod(den, fieldP)
	if den.Sign() == 0 {
		return true // identity
	}
	u := new(big.Int).Add(big.NewInt(1), y)
	u.Mul(u, new(big.Int).ModInverse(den, fieldP)).Mod(u, fieldP)
	be := u.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	pub, err := ecdh.X25519().NewPublicKey(be)
	if err != nil {
		return true
	}
	_, err = x25519Scalar.ECDH(pub)
	return err != nil
}

var x25519Scalar = func() *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		panic(err)
	}
	return k
}()
