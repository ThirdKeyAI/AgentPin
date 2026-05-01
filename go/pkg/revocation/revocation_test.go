package revocation

import (
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func TestBuildAndAddRevocations(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	if d.Entity != "example.com" {
		t.Fatal("entity")
	}
	if len(d.RevokedCredentials) != 0 {
		t.Fatal("should start empty")
	}
	AddRevokedCredential(&d, "jti-1", types.ReasonKeyCompromise)
	AddRevokedAgent(&d, "agent-1", types.ReasonPolicyViolation)
	AddRevokedKey(&d, "kid-1", types.ReasonSuperseded)
	if len(d.RevokedCredentials) != 1 || len(d.RevokedAgents) != 1 || len(d.RevokedKeys) != 1 {
		t.Fatal("expected 1 each")
	}
}

func TestCheckRevocationClean(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	if err := CheckRevocation(&d, "j", "a", "k"); err != nil {
		t.Fatalf("clean check should pass: %v", err)
	}
}

func TestCheckRevocationCredentialRevoked(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	AddRevokedCredential(&d, "jti-bad", types.ReasonKeyCompromise)
	err := CheckRevocation(&d, "jti-bad", "a", "k")
	if err == nil {
		t.Fatal("revoked jti should fail")
	}
	ve, ok := types.AsVerificationError(err)
	if !ok || ve.Code != types.ErrCredentialRevoked {
		t.Fatalf("expected CredentialRevoked, got %v", err)
	}
}

func TestCheckRevocationAgentRevoked(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	AddRevokedAgent(&d, "bad-agent", types.ReasonPrivilegeWithdrawn)
	if err := CheckRevocation(&d, "j", "bad-agent", "k"); err == nil {
		t.Fatal("revoked agent should fail")
	}
}

func TestCheckRevocationKeyRevoked(t *testing.T) {
	d := BuildRevocationDocument("example.com")
	AddRevokedKey(&d, "bad-key", types.ReasonSuperseded)
	if err := CheckRevocation(&d, "j", "a", "bad-key"); err == nil {
		t.Fatal("revoked key should fail")
	}
}
