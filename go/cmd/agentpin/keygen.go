package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
)

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	domain := fs.String("domain", "", "Domain this key is associated with (required)")
	kid := fs.String("kid", "", "Key identifier, e.g. 'example-2026-01' (required)")
	outputDir := fs.String("output-dir", ".", "Output directory for key files")
	format := fs.String("format", "both", "Output format: jwk, pem, or both")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" || *kid == "" {
		return fmt.Errorf("--domain and --kid are required")
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return err
	}

	privPath := filepath.Join(*outputDir, *kid+".private.pem")
	if err := os.WriteFile(privPath, []byte(kp.PrivateKeyPEM), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Generated ECDSA P-256 keypair for domain", *domain, "(kid:", *kid+")")
	fmt.Fprintln(os.Stderr, "  Private key:", privPath)

	if *format == "pem" || *format == "both" {
		pubPath := filepath.Join(*outputDir, *kid+".public.pem")
		if err := os.WriteFile(pubPath, []byte(kp.PublicKeyPEM), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "  Public key (PEM):", pubPath)
	}
	if *format == "jwk" || *format == "both" {
		j, err := jwk.PEMToJWK(kp.PublicKeyPEM, *kid)
		if err != nil {
			return err
		}
		jb, err := json.MarshalIndent(j, "", "  ")
		if err != nil {
			return err
		}
		jwkPath := filepath.Join(*outputDir, *kid+".public.jwk.json")
		if err := os.WriteFile(jwkPath, jb, 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "  Public key (JWK):", jwkPath)
	}

	return nil
}
