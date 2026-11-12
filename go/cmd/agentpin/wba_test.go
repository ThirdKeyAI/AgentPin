package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
	"github.com/ThirdKeyAi/agentpin/go/pkg/jwt"
	"github.com/ThirdKeyAi/agentpin/go/pkg/wba"
)

// capture runs f with stdout redirected and returns what it printed.
func capture(t *testing.T, f func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	runErr := f()
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatal(runErr)
	}
	return string(out)
}

func TestWbaKeygenDirectorySignAndIssue(t *testing.T) {
	dir := t.TempDir()
	keyid := strings.TrimSpace(capture(t, func() error {
		return runWba([]string{"keygen", "--name", "crawler", "--output-dir", dir})
	}))
	keyPath := filepath.Join(dir, "crawler.ed25519.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := runWba([]string{"keygen", "--name", "crawler", "--output-dir", dir}); err == nil {
		t.Fatal("overwrite without --force")
	}
	if err := runWba([]string{"keygen", "--name", "../x", "--output-dir", dir}); err == nil {
		t.Fatal("path-like name accepted")
	}

	out := capture(t, func() error { return runWba([]string{"directory", "--key", keyPath}) })
	d, err := wba.ParseDirectory([]byte(out))
	if err != nil || len(d.Keys) != 1 || d.Keys[0].Thumbprint() != keyid {
		t.Fatalf("directory %s: %v", out, err)
	}

	agent := "https://example.com/.well-known/http-message-signatures-directory"
	out = capture(t, func() error {
		return runWba([]string{"sign", "--key", keyPath, "--signature-agent", agent,
			"--url", "https://shop.example/p?q=1", "--header", "X-Test: v", "--query-param", "q"})
	})
	req, _ := httpsig.NewRequest("GET", "https://shop.example/p?q=1")
	req.Header("X-Test", "v")
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		name, value, _ := strings.Cut(line, ": ")
		req.Header(name, value)
	}
	store := wba.NewDirectoryKeyStore()
	if err := store.Insert(agent, d); err != nil {
		t.Fatal(err)
	}
	o := wba.VerifyRequest(req, store, wba.DefaultVerifyOptions())
	if o.Kind != wba.Verified || !o.Agent.Covers(httpsig.NewComponent("x-test")) || !o.Agent.Covers(httpsig.QueryParam("q")) {
		t.Fatalf("%v", o)
	}

	// issue --wba-jkt carries the keyid as cnf.jkt.
	if err := runKeygen([]string{"--domain", "example.com", "--kid", "k1", "--output-dir", dir}); err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(capture(t, func() error {
		return runIssue([]string{"--private-key", filepath.Join(dir, "k1.private.pem"), "--kid", "k1",
			"--issuer", "example.com", "--agent-id", "urn:agentpin:example.com:crawler",
			"--capabilities", "read:pages", "--wba-jkt", keyid})
	}))
	_, payload, _, err := jwt.DecodeJWTUnverified(token)
	if err != nil || payload.Cnf == nil || payload.Cnf.Jkt != keyid {
		t.Fatalf("%+v %v", payload, err)
	}
	if err := runIssue([]string{"--private-key", filepath.Join(dir, "k1.private.pem"), "--kid", "k1",
		"--issuer", "example.com", "--agent-id", "urn:agentpin:example.com:crawler",
		"--capabilities", "read:pages", "--wba-jkt", "bad"}); err == nil {
		t.Fatal("malformed --wba-jkt accepted")
	}
}
