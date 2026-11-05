package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
	"github.com/ThirdKeyAi/agentpin/go/pkg/wba"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func wbaUsage() {
	fmt.Fprintln(os.Stderr, `agentpin wba — Web Bot Auth keys, key directories and request signing

USAGE:
    agentpin wba <COMMAND> [OPTIONS]

COMMANDS:
    keygen       Generate an Ed25519 signing key; prints its keyid (JWK thumbprint)
    directory    Print the key directory (JWK Set) for one or more keys
    sign         Sign a request and print the Signature-Agent, Signature-Input
                 and Signature headers`)
}

func runWba(args []string) error {
	if len(args) == 0 {
		wbaUsage()
		return errors.New("missing wba command")
	}
	switch args[0] {
	case "keygen":
		return runWbaKeygen(args[1:])
	case "directory":
		return runWbaDirectory(args[1:])
	case "sign":
		return runWbaSign(args[1:])
	case "-h", "--help", "help":
		wbaUsage()
		return nil
	}
	wbaUsage()
	return fmt.Errorf("unknown wba command: %s", args[0])
}

func loadWbaKey(path string) (wba.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wba.PrivateKey{}, err
	}
	k, err := wba.LoadSigningKey(string(data))
	if err != nil {
		return wba.PrivateKey{}, fmt.Errorf("%s: %w", path, err)
	}
	return k, nil
}

func runWbaKeygen(args []string) error {
	fs := flag.NewFlagSet("wba keygen", flag.ContinueOnError)
	name := fs.String("name", "", "File name stem for the key (letters, digits, '.', '_' and '-') (required)")
	outputDir := fs.String("output-dir", ".", "Output directory")
	force := fs.Bool("force", false, "Overwrite an existing key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("--name is required")
	}
	if err := validateKid(*name); err != nil {
		return err
	}
	key, err := wba.GenerateSigningKey()
	if err != nil {
		return err
	}
	pem, err := wba.SigningKeyToPEM(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(*outputDir, *name+".ed25519.pem")
	if err := writeNewFile(path, []byte(pem), 0o600, *force); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Generated Ed25519 Web Bot Auth key: %s (mode 0600)\n", path)
	fmt.Println(wba.Thumbprint(key.PublicKey()))
	return nil
}

func runWbaDirectory(args []string) error {
	fs := flag.NewFlagSet("wba directory", flag.ContinueOnError)
	var keys stringList
	fs.Var(&keys, "key", "Ed25519 or RSA private key PEM (repeat for rotation) (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("--key is required")
	}
	var public []wba.PublicKey
	for _, p := range keys {
		k, err := loadWbaKey(p)
		if err != nil {
			return err
		}
		public = append(public, k.PublicKey())
	}
	out, err := wba.DirectoryFromKeys(public...).PrettyJSON()
	if err != nil {
		return err
	}
	fmt.Println(string(out))
	return nil
}

func runWbaSign(args []string) error {
	fs := flag.NewFlagSet("wba sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "Ed25519 or RSA (2048-8192 bit, signs with rsa-pss-sha512) private key PEM (required)")
	agent := fs.String("signature-agent", "", "HTTPS URL of the key directory publishing this key (required)")
	url := fs.String("url", "", "Request URL (required)")
	method := fs.String("method", "GET", "Request method")
	var headers, queryParams stringList
	fs.Var(&headers, "header", `Header to send and cover, as "Name: value" (repeatable)`)
	fs.Var(&queryParams, "query-param", "Query parameter to cover with @query-param (repeatable)")
	validity := fs.Int64("validity", 300, "Signature lifetime in seconds (max 86400)")
	legacy := fs.Bool("legacy-signature-agent", false, "Send the legacy bare-String Signature-Agent, for verifiers that predate the Dictionary form")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *agent == "" || *url == "" {
		return errors.New("--key, --signature-agent and --url are required")
	}
	key, err := loadWbaKey(*keyPath)
	if err != nil {
		return err
	}
	req, err := httpsig.NewRequest(*method, *url)
	if err != nil {
		return err
	}
	opts := wba.DefaultSignOptions()
	opts.ValiditySecs = *validity
	opts.LegacySignatureAgent = *legacy
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return errors.New(`--header must be "Name: value"`)
		}
		name = strings.TrimSpace(name)
		req.Header(name, strings.TrimSpace(value))
		c := httpsig.NewComponent(strings.ToLower(name))
		if !containsComponent(opts.Components, c) {
			opts.Components = append(opts.Components, c)
		}
	}
	for _, q := range queryParams {
		opts.Components = append(opts.Components, httpsig.QueryParam(q))
	}
	signed, err := wba.SignRequest(req, key, *agent, opts)
	if err != nil {
		return err
	}
	for _, h := range signed.Headers() {
		fmt.Printf("%s: %s\n", h.Name, h.Value)
	}
	return nil
}

func containsComponent(cs []httpsig.Component, c httpsig.Component) bool {
	for _, x := range cs {
		if x == c {
			return true
		}
	}
	return false
}
