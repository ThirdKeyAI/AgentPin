package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/crypto"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwk"
)

func runKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	domain := fs.String("domain", "", "Domain this key is associated with (required)")
	kid := fs.String("kid", "", "Key identifier, e.g. 'example-2026-01' (required)")
	outputDir := fs.String("output-dir", ".", "Output directory for key files")
	format := fs.String("format", "both", "Output format: jwk, pem, or both")
	force := fs.Bool("force", false, "Overwrite existing key files (by default an existing file is an error)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" || *kid == "" {
		return fmt.Errorf("--domain and --kid are required")
	}

	if err := validateKid(*kid); err != nil {
		return err
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return err
	}

	privPath := filepath.Join(*outputDir, *kid+".private.pem")
	if err := writeNewFile(privPath, []byte(kp.PrivateKeyPEM), 0o600, *force); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Generated ECDSA P-256 keypair for domain", *domain, "(kid:", *kid+")")
	fmt.Fprintln(os.Stderr, "  Private key:", privPath, "(mode 0600)")

	if *format == "pem" || *format == "both" {
		pubPath := filepath.Join(*outputDir, *kid+".public.pem")
		if err := writeNewFile(pubPath, []byte(kp.PublicKeyPEM), 0o644, *force); err != nil {
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
		if err := writeNewFile(jwkPath, jb, 0o644, *force); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "  Public key (JWK):", jwkPath)
	}

	return nil
}

// validateKid rejects key ids that could escape --output-dir or collide
// with path syntax (AP-16).
func validateKid(kid string) error {
	if kid == "" || len(kid) > 128 || kid == "." || kid == ".." || strings.Contains(kid, "..") {
		return fmt.Errorf("invalid --kid %q: use letters, digits, '.', '_' and '-' only (no path separators)", kid)
	}
	for i, r := range kid {
		alnum := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if i == 0 && !alnum {
			return fmt.Errorf("invalid --kid %q: must start with a letter or digit", kid)
		}
		if !alnum && r != '.' && r != '_' && r != '-' {
			return fmt.Errorf("invalid --kid %q: use letters, digits, '.', '_' and '-' only (no path separators)", kid)
		}
	}
	return nil
}

// writeNewFile creates path with mode, refusing to overwrite unless force.
// The mode is applied at creation and re-applied after an overwrite.
func writeNewFile(path string, contents []byte, mode os.FileMode, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if force {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, mode)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
		return err
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
