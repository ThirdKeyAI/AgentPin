package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/pinning"
	"github.com/ThirdKeyAi/agentpin/go/pkg/resolver"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
	"github.com/ThirdKeyAi/agentpin/go/pkg/verification"
)

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	credentialArg := fs.String("credential", "", "JWT credential string or file path (required)")
	discoveryPath := fs.String("discovery", "", "Path to discovery document JSON file (offline)")
	revocationPath := fs.String("revocation", "", "Path to revocation document JSON file (offline)")
	pinStorePath := fs.String("pin-store", "", "Path to pin store JSON file")
	audience := fs.String("audience", "", "Verifier's audience domain")
	offline := fs.Bool("offline", false, "Use offline-only verification")
	trustBundlePath := fs.String("trust-bundle", "", "Trust bundle JSON file for resolver mode")
	discoveryDir := fs.String("discovery-dir", "", "Directory of {domain}.json discovery files for resolver mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *credentialArg == "" {
		return fmt.Errorf("--credential is required")
	}

	cred := *credentialArg
	if _, err := os.Stat(cred); err == nil {
		data, err := os.ReadFile(cred)
		if err != nil {
			return err
		}
		cred = strings.TrimSpace(string(data))
	}

	pinStore := pinning.NewKeyPinStore()
	if *pinStorePath != "" {
		if data, err := os.ReadFile(*pinStorePath); err == nil {
			if err := pinStore.LoadFromJSON(data); err != nil {
				return fmt.Errorf("load pin store: %w", err)
			}
		}
	}
	cfg := verification.DefaultVerifierConfig()

	var result verification.Result
	if *trustBundlePath != "" || *discoveryDir != "" {
		r, err := buildResolver(*trustBundlePath, *discoveryDir)
		if err != nil {
			return err
		}
		result = verification.VerifyCredentialWithResolver(cred, r, pinStore, *audience, cfg)
	} else if *offline || *discoveryPath != "" {
		if *discoveryPath == "" {
			return fmt.Errorf("--discovery is required for offline verification")
		}
		dData, err := os.ReadFile(*discoveryPath)
		if err != nil {
			return err
		}
		var disc types.DiscoveryDocument
		if err := json.Unmarshal(dData, &disc); err != nil {
			return err
		}
		var rev *types.RevocationDocument
		if *revocationPath != "" {
			rData, err := os.ReadFile(*revocationPath)
			if err != nil {
				return err
			}
			var r types.RevocationDocument
			if err := json.Unmarshal(rData, &r); err != nil {
				return err
			}
			rev = &r
		}
		result = verification.VerifyCredentialOffline(cred, &disc, rev, pinStore, *audience, cfg)
	} else {
		// Online verification via WellKnownResolver.
		r := resolver.NewWellKnownResolver()
		result = verification.VerifyCredentialWithResolver(cred, r, pinStore, *audience, cfg)
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(out))

	// Persist the pin store atomically (temp file + rename) with restrictive
	// permissions; a write failure is reported, not ignored (AP-16).
	if *pinStorePath != "" {
		data, err := pinStore.MarshalJSON()
		if err != nil {
			return fmt.Errorf("serialize pin store: %w", err)
		}
		if err := writeAtomic(*pinStorePath, data, 0o600); err != nil {
			return fmt.Errorf("persist pin store: %w", err)
		}
	}

	if !result.Valid {
		os.Exit(1)
	}
	return nil
}

func buildResolver(trustBundlePath, discoveryDir string) (resolver.DiscoveryResolver, error) {
	resolvers := []resolver.DiscoveryResolver{}
	if trustBundlePath != "" {
		data, err := os.ReadFile(trustBundlePath)
		if err != nil {
			return nil, err
		}
		r, err := resolver.TrustBundleResolverFromJSON(data)
		if err != nil {
			return nil, err
		}
		resolvers = append(resolvers, r)
	}
	if discoveryDir != "" {
		resolvers = append(resolvers, resolver.NewLocalFileResolver(discoveryDir, ""))
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("at least --trust-bundle or --discovery-dir must be provided")
	}
	if len(resolvers) == 1 {
		return resolvers[0], nil
	}
	return resolver.NewChainResolver(resolvers), nil
}

// writeAtomic writes contents to path via a sibling temp file and rename.
func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(contents); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
