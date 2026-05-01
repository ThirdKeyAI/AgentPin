package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/pkg/bundle"
	"github.com/ThirdKeyAi/agentpin/go/pkg/types"
)

// stringSlice is a flag.Value for --discovery / --revocation that can be
// repeated.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func runBundle(args []string) error {
	fs := flag.NewFlagSet("bundle", flag.ContinueOnError)
	var discFiles stringSlice
	var revFiles stringSlice
	fs.Var(&discFiles, "discovery", "Path to a discovery document JSON file (repeatable)")
	fs.Var(&revFiles, "revocation", "Path to a revocation document JSON file (repeatable)")
	output := fs.String("output", "", "Output path (defaults to stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(discFiles) == 0 {
		return fmt.Errorf("at least one --discovery file is required")
	}

	b := bundle.NewTrustBundle(time.Now().UTC().Format(time.RFC3339))
	for _, p := range discFiles {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var d types.DiscoveryDocument
		if err := json.Unmarshal(data, &d); err != nil {
			return fmt.Errorf("invalid discovery document %s: %w", p, err)
		}
		b.Documents = append(b.Documents, d)
	}
	for _, p := range revFiles {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var r types.RevocationDocument
		if err := json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("invalid revocation document %s: %w", p, err)
		}
		b.Revocations = append(b.Revocations, r)
	}

	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if *output != "" {
		if err := os.WriteFile(*output, out, 0o644); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Trust bundle written to", *output)
	} else {
		fmt.Println(string(out))
	}
	return nil
}
