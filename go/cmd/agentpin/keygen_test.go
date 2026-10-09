package main

import (
	"os"
	"path/filepath"
	"testing"
)

// AP-16: keygen must create the private key 0600, refuse to overwrite
// without --force, and reject path-like key ids.
func TestKeygenPermissionsAndOverwrite(t *testing.T) {
	dir := t.TempDir()
	if err := runKeygen([]string{"--domain", "example.com", "--kid", "k1", "--output-dir", dir}); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(dir, "k1.private.pem")
	info, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("private key mode %o, want 0600", mode)
	}
	first, _ := os.ReadFile(priv)
	if err := runKeygen([]string{"--domain", "example.com", "--kid", "k1", "--output-dir", dir}); err == nil {
		t.Fatal("second keygen must refuse to overwrite")
	}
	if again, _ := os.ReadFile(priv); string(again) != string(first) {
		t.Fatal("existing key was modified")
	}
	if err := runKeygen([]string{"--domain", "example.com", "--kid", "k1", "--output-dir", dir, "--force"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(priv); string(again) == string(first) {
		t.Fatal("--force should have regenerated the key")
	}
}

func TestKeygenRejectsPathLikeKid(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"../../x", "/tmp/x", "a/b", "..", ".", "a..b", "-x", ""} {
		if err := runKeygen([]string{"--domain", "example.com", "--kid", bad, "--output-dir", dir}); err == nil {
			t.Fatalf("kid %q accepted", bad)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("nothing should have been written: %v", entries)
	}
}

func TestWriteAtomicCreatesRestrictiveFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	if err := writeAtomic(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode %o, want 0600", mode)
	}
	if err := writeAtomic(path, []byte("[1]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "[1]" {
		t.Fatal("overwrite failed")
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".pins.json.tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("temp files left behind: %v", leftovers)
	}
}
