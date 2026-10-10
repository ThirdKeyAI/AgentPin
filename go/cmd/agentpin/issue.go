package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/credential"
	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

func runIssue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	privKeyPath := fs.String("private-key", "", "Path to private key PEM file (required)")
	kid := fs.String("kid", "", "Key identifier (required)")
	issuer := fs.String("issuer", "", "Issuer domain (required)")
	agentID := fs.String("agent-id", "", "Agent URN (required)")
	audience := fs.String("audience", "", "Audience domain (optional)")
	caps := fs.String("capabilities", "", "Comma-separated capabilities (required)")
	ttl := fs.Uint64("ttl", 3600, "Credential TTL in seconds")
	delChainPath := fs.String("delegation-chain", "", "JSON file with delegation chain entries")
	constraintsArg := fs.String("constraints", "", "JSON string with constraint overrides (literal; use --constraints-file for a file)")
	constraintsFile := fs.String("constraints-file", "", "Path to a JSON file with constraint overrides")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *privKeyPath == "" || *kid == "" || *issuer == "" || *agentID == "" || *caps == "" {
		return fmt.Errorf("--private-key, --kid, --issuer, --agent-id, --capabilities are required")
	}

	pemData, err := os.ReadFile(*privKeyPath)
	if err != nil {
		return err
	}
	priv, err := crypto.LoadPrivateKey(string(pemData))
	if err != nil {
		return err
	}

	capList := []types.Capability{}
	for _, c := range strings.Split(*caps, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		capList = append(capList, types.Capability(c))
	}

	var constraints *types.Constraints
	if *constraintsArg != "" && *constraintsFile != "" {
		return fmt.Errorf("use only one of --constraints or --constraints-file")
	}
	if *constraintsArg != "" || *constraintsFile != "" {
		// --constraints is always literal JSON and --constraints-file always a
		// path (AP-23).
		data := []byte(*constraintsArg)
		if *constraintsFile != "" {
			var err error
			data, err = os.ReadFile(*constraintsFile)
			if err != nil {
				return err
			}
		}
		var c types.Constraints
		if err := json.Unmarshal(data, &c); err != nil {
			return fmt.Errorf("invalid constraints JSON: %w", err)
		}
		constraints = &c
	}

	var chain []types.DelegationAttestation
	if *delChainPath != "" {
		data, err := os.ReadFile(*delChainPath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &chain); err != nil {
			return fmt.Errorf("invalid delegation chain JSON: %w", err)
		}
	}

	jwt, err := credential.IssueCredential(priv, *kid, *issuer, *agentID, *audience, capList, constraints, chain, *ttl)
	if err != nil {
		return err
	}
	fmt.Println(jwt)
	return nil
}
