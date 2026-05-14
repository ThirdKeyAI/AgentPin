package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Capability is an AgentPin capability in the canonical "action:resource"
// format. It serializes as a JSON string for wire compatibility with the
// Rust, JavaScript, and Python SDKs.
type Capability string

// NewCapability constructs a capability from an action/resource pair.
func NewCapability(action, resource string) Capability {
	return Capability(action + ":" + resource)
}

// Action returns the action component of the capability, or "" if the
// capability is malformed.
func (c Capability) Action() string {
	a, _, ok := c.split()
	if !ok {
		return ""
	}
	return a
}

// Resource returns the resource component of the capability, or "" if the
// capability is malformed.
func (c Capability) Resource() string {
	_, r, ok := c.split()
	if !ok {
		return ""
	}
	return r
}

// String returns the canonical "action:resource" representation.
func (c Capability) String() string { return string(c) }

func (c Capability) split() (string, string, bool) {
	idx := strings.IndexByte(string(c), ':')
	if idx < 0 {
		return "", "", false
	}
	return string(c)[:idx], string(c)[idx+1:], true
}

// Matches reports whether a declared capability covers a requested capability.
//
// Wildcard resources ("*") match any resource for the same action. Scoped
// resources match if the requested resource starts with the declared resource
// followed by "." (e.g., "read:codebase" matches
// "read:codebase.github.com/org/repo").
func (c Capability) Matches(requested Capability) bool {
	declAction, declRes, ok := c.split()
	if !ok {
		return false
	}
	reqAction, reqRes, ok := requested.split()
	if !ok {
		return false
	}
	if declAction != reqAction {
		return false
	}
	if declRes == "*" || declRes == reqRes {
		return true
	}
	if strings.HasPrefix(reqRes, declRes) && len(reqRes) > len(declRes) && reqRes[len(declRes)] == '.' {
		return true
	}
	return false
}

// CoreActions lists the AgentPin core action verbs.
var CoreActions = []string{"read", "write", "execute", "admin", "delegate"}

// isReverseDomain reports whether action looks like a reverse-domain prefix
// (e.g., "com.example.scan"). It requires at least two non-empty
// dot-separated segments.
func isReverseDomain(action string) bool {
	parts := strings.Split(action, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
	}
	return true
}

// ValidateCapability validates a capability against the AgentPin taxonomy.
//
//   - Must be in "action:resource" format.
//   - Core actions ("read", "write", "execute", "admin", "delegate") are
//     always valid (with any resource), with one exception:
//   - "admin:*" is rejected — admin must be explicitly scoped.
//   - Custom (non-core) actions MUST use a reverse-domain prefix (e.g.,
//     "com.example.scan:target").
func ValidateCapability(c Capability) error {
	action, resource, ok := c.split()
	if !ok {
		return fmt.Errorf("capability must be in 'action:resource' format")
	}
	if action == "admin" && resource == "*" {
		return fmt.Errorf("admin:* wildcard is not allowed; admin capabilities must be explicitly scoped")
	}
	for _, ca := range CoreActions {
		if ca == action {
			return nil
		}
	}
	if !isReverseDomain(action) {
		return fmt.Errorf("custom action '%s' must use reverse-domain prefix (e.g., com.example.%s)", action, action)
	}
	return nil
}

// CapabilitiesSubset reports whether every requested capability is covered by
// at least one declared capability.
func CapabilitiesSubset(declared, requested []Capability) bool {
	for _, req := range requested {
		matched := false
		for _, decl := range declared {
			if decl.Matches(req) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// CapabilitiesHash hashes a list of capabilities deterministically by sorting
// them alphabetically, JSON-encoding the sorted array, and SHA-256 hashing
// the result. Used by the delegation attestation flow.
func CapabilitiesHash(caps []Capability) string {
	strs := make([]string, len(caps))
	for i, c := range caps {
		strs[i] = string(c)
	}
	sort.Strings(strs)
	b, err := json.Marshal(strs)
	if err != nil {
		// json.Marshal on []string never errors in practice.
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
