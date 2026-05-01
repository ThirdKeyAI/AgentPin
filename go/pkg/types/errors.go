// Package types contains shared AgentPin types used across the SDK packages:
// JWK, capabilities, constraints, discovery / credential / revocation /
// trust-bundle / pinning / mutual-auth structures, and the unified ErrorCode
// taxonomy from spec section 6.7.
package types

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrorCode enumerates the verification failure codes from the AgentPin spec
// (section 6.7). They serialize as their canonical SCREAMING_SNAKE_CASE
// strings so JSON output matches the Rust/JavaScript/Python ports verbatim.
type ErrorCode string

const (
	ErrSignatureInvalid        ErrorCode = "SIGNATURE_INVALID"
	ErrKeyNotFound             ErrorCode = "KEY_NOT_FOUND"
	ErrKeyExpired              ErrorCode = "KEY_EXPIRED"
	ErrKeyRevoked              ErrorCode = "KEY_REVOKED"
	ErrCredentialExpired       ErrorCode = "CREDENTIAL_EXPIRED"
	ErrCredentialRevoked       ErrorCode = "CREDENTIAL_REVOKED"
	ErrAgentNotFound           ErrorCode = "AGENT_NOT_FOUND"
	ErrAgentInactive           ErrorCode = "AGENT_INACTIVE"
	ErrCapabilityExceeded      ErrorCode = "CAPABILITY_EXCEEDED"
	ErrConstraintViolation     ErrorCode = "CONSTRAINT_VIOLATION"
	ErrDelegationInvalid       ErrorCode = "DELEGATION_INVALID"
	ErrDelegationDepthExceeded ErrorCode = "DELEGATION_DEPTH_EXCEEDED"
	ErrDiscoveryFetchFailed    ErrorCode = "DISCOVERY_FETCH_FAILED"
	ErrDiscoveryInvalid        ErrorCode = "DISCOVERY_INVALID"
	ErrDomainMismatch          ErrorCode = "DOMAIN_MISMATCH"
	ErrAudienceMismatch        ErrorCode = "AUDIENCE_MISMATCH"
	ErrAlgorithmRejected       ErrorCode = "ALGORITHM_REJECTED"
	ErrKeyPinMismatch          ErrorCode = "KEY_PIN_MISMATCH"
)

// VerificationError is returned by verification helpers that need to surface
// a typed failure code alongside a human-readable message.
type VerificationError struct {
	Code    ErrorCode
	Message string
}

// Error implements the error interface.
func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NewVerificationError constructs a VerificationError.
func NewVerificationError(code ErrorCode, msg string) *VerificationError {
	return &VerificationError{Code: code, Message: msg}
}

// AsVerificationError extracts a *VerificationError from err if present.
func AsVerificationError(err error) (*VerificationError, bool) {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve, true
	}
	return nil, false
}

// MarshalJSON renders the ErrorCode as a JSON string.
func (c ErrorCode) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(c))
}

// UnmarshalJSON reads an ErrorCode from a JSON string.
func (c *ErrorCode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*c = ErrorCode(s)
	return nil
}
