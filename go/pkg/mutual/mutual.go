// Package mutual implements the AgentPin challenge / response mutual-auth
// flow with 128-bit random nonces.
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

const nonceExpirySecs = int64(60)

// CreateChallenge produces a fresh challenge with a 128-bit random nonce.
// verifierCredential may be empty to omit the field.
func CreateChallenge(verifierCredential string) (*types.Challenge, error) {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return nil, fmt.Errorf("read random nonce: %w", err)
	}
	return &types.Challenge{
		Type:               "agentpin-challenge",
		Nonce:              base64.RawURLEncoding.EncodeToString(n[:]),
		Timestamp:          time.Now().UTC().Format(time.RFC3339),
		VerifierCredential: verifierCredential,
	}, nil
}

// CreateResponse signs the challenge nonce with priv and returns a Response.
func CreateResponse(challenge *types.Challenge, priv *ecdsa.PrivateKey, kid string) (*types.Response, error) {
	sig, err := crypto.SignBytes(priv, []byte(challenge.Nonce))
	if err != nil {
		return nil, err
	}
	return &types.Response{
		Type:      "agentpin-response",
		Nonce:     challenge.Nonce,
		Signature: sig,
		Kid:       kid,
	}, nil
}

// VerifyResponse checks the response nonce, expiry, and signature. It does
// not perform replay protection — see VerifyResponseWithStore for that.
func VerifyResponse(response *types.Response, challenge *types.Challenge, pub *ecdsa.PublicKey) (bool, error) {
	return VerifyResponseWithStore(response, challenge, pub, nil)
}

// VerifyResponseWithStore checks the response and (optionally) records the
// nonce in store to reject replays. Returns false (and no error) when the
// nonce simply doesn't match; returns an error for expired nonce, replay,
// or signature decode failure.
func VerifyResponseWithStore(response *types.Response, challenge *types.Challenge, pub *ecdsa.PublicKey, store nonce.Store) (bool, error) {
	if response.Nonce != challenge.Nonce {
		return false, nil
	}

	if challenge.Timestamp != "" {
		ts, err := time.Parse(time.RFC3339, challenge.Timestamp)
		if err == nil {
			elapsed := time.Now().Unix() - ts.Unix()
			if elapsed > nonceExpirySecs {
				return false, fmt.Errorf("Challenge nonce expired (%d seconds old, max %d)", elapsed, nonceExpirySecs)
			}
		}
	}

	if store != nil {
		fresh, err := store.CheckAndRecord(response.Nonce, time.Duration(nonceExpirySecs)*time.Second)
		if err != nil {
			return false, err
		}
		if !fresh {
			return false, errors.New("Nonce has already been used")
		}
	}

	return crypto.VerifyBytes(pub, []byte(challenge.Nonce), response.Signature)
}
