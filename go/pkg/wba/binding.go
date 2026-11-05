package wba

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/domain"
	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"github.com/ThirdKeyAi/agentpin/go/pkg/verification"
)

// AuthorizationPrefix prefixes the credential in the Authorization field.
const AuthorizationPrefix = "AgentPin "

// FormatAuthorizationHeader returns "AgentPin <jwt>".
func FormatAuthorizationHeader(credentialJWT string) string {
	return AuthorizationPrefix + credentialJWT
}

// RequestCredential returns the AgentPin credential JWT carried in the
// request's "Authorization: AgentPin <jwt>" field.
func RequestCredential(req *httpsig.Request) (string, error) {
	auth, ok := httpsig.CombinedField(req.Headers, "authorization")
	if !ok {
		return "", wbaErr("request has no Authorization field")
	}
	token, ok := strings.CutPrefix(auth, AuthorizationPrefix)
	if !ok {
		return "", errors.New("missing 'AgentPin ' prefix in Authorization header")
	}
	if token == "" {
		return "", errors.New("empty credential in Authorization header")
	}
	return token, nil
}

// CheckBinding checks that a verified WBA signature and a verified
// AgentPin credential describe the same agent:
//
//  1. the credential verified, and the signature covers authorization, so
//     the credential is bound to this signed request;
//  2. the credential's cnf.jkt equals the signature's keyid;
//  3. disc is the issuer's document, and it vouches for the
//     Signature-Agent URL: listed in web_bot_auth.signature_agents, or,
//     when that field is absent, the issuer's well-known directory.
func CheckBinding(agent *VerifiedAgent, req *httpsig.Request, credential *verification.Result, disc *types.DiscoveryDocument) error {
	if !credential.Valid {
		return errors.New("AgentPin credential did not verify")
	}
	if !agent.Covers(httpsig.NewComponent("authorization")) {
		return errors.New("Web Bot Auth signature does not cover the Authorization field")
	}
	token, err := RequestCredential(req)
	if err != nil {
		return err
	}
	_, payload, _, err := jwt.DecodeJWTUnverified(token)
	if err != nil {
		return err
	}
	if payload.Cnf == nil {
		return errors.New("credential has no cnf.jkt key confirmation")
	}
	if payload.Cnf.Jkt != agent.KeyID {
		return errors.New("credential cnf.jkt does not match the signature keyid")
	}
	issuer, err := domain.Normalize(payload.Iss)
	if err != nil {
		return err
	}
	resultIssuer, err := domain.Normalize(credential.Issuer)
	if err != nil || resultIssuer != issuer || credential.AgentID != payload.Sub {
		return errors.New("credential result does not belong to this request")
	}
	entity, err := domain.Normalize(disc.Entity)
	if err != nil {
		return err
	}
	if issuer != entity {
		return errors.New("discovery document is not the credential issuer's")
	}
	allowed := false
	if disc.WebBotAuth != nil {
		for _, u := range disc.WebBotAuth.SignatureAgents {
			if n, err := NormalizeSignatureAgent(u); err == nil && n == agent.SignatureAgent {
				allowed = true
				break
			}
		}
	} else if n, err := NormalizeSignatureAgent(WellKnownDirectory(entity)); err == nil && n == agent.SignatureAgent {
		allowed = true
	}
	if !allowed {
		return fmt.Errorf("%s does not vouch for Signature-Agent %s", entity, agent.SignatureAgent)
	}
	return nil
}

// BoundAgent is a request whose WBA signature and AgentPin credential
// verified and are bound to each other.
type BoundAgent struct {
	Agent      *VerifiedAgent
	Credential verification.Result
}

// FailureKind says which stage of VerifyBoundRequest failed.
type FailureKind int

const (
	// FailureWBA: the WBA signature did not verify (see Outcome).
	FailureWBA FailureKind = iota
	// FailureCredential: the AgentPin credential did not verify (see
	// Credential).
	FailureCredential
	// FailureBinding: both verified but they are not bound to each other
	// (see Reason).
	FailureBinding
)

// BindingFailure is the error VerifyBoundRequest returns.
type BindingFailure struct {
	Kind       FailureKind
	Outcome    Outcome
	Credential *verification.Result
	Reason     string
}

func (f *BindingFailure) Error() string {
	switch f.Kind {
	case FailureWBA:
		return "Web Bot Auth " + f.Outcome.String()
	case FailureCredential:
		return fmt.Sprintf("AgentPin credential invalid: %s: %s", f.Credential.ErrorCode, f.Credential.ErrorMessage)
	}
	return "binding failed: " + f.Reason
}

// VerifyBoundRequest verifies a request's WBA signature, its AgentPin
// credential, and the binding between them (CheckBinding). Failures are
// returned as *BindingFailure.
func VerifyBoundRequest(
	req *httpsig.Request,
	keys KeyLookup,
	r resolver.DiscoveryResolver,
	pinStore *pinning.KeyPinStore,
	audience string,
	wbaOpts VerifyOptions,
	config verification.VerifierConfig,
) (*BoundAgent, error) {
	o := VerifyRequest(req, keys, wbaOpts)
	if o.Kind != Verified {
		return nil, &BindingFailure{Kind: FailureWBA, Outcome: o}
	}
	token, err := RequestCredential(req)
	if err != nil {
		return nil, &BindingFailure{Kind: FailureBinding, Reason: err.Error()}
	}
	cred := verification.VerifyCredentialWithResolver(token, r, pinStore, audience, config)
	if !cred.Valid {
		return nil, &BindingFailure{Kind: FailureCredential, Credential: &cred}
	}
	disc, err := r.ResolveDiscovery(cred.Issuer)
	if err != nil {
		return nil, &BindingFailure{Kind: FailureBinding, Reason: err.Error()}
	}
	if err := CheckBinding(o.Agent, req, &cred, disc); err != nil {
		return nil, &BindingFailure{Kind: FailureBinding, Reason: err.Error()}
	}
	return &BoundAgent{Agent: o.Agent, Credential: cred}, nil
}
