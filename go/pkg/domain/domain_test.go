package domain

import (
	"strings"
	"testing"
)

func TestNormalizeCanonicalizes(t *testing.T) {
	cases := map[string]string{
		"example.com":           "example.com",
		"EXAMPLE.COM":           "example.com",
		"Example.Com.":          "example.com",
		"bücher.example":        "xn--bcher-kva.example",
		"XN--BCHER-KVA.example": "xn--bcher-kva.example",
		"localhost":             "localhost",
		"a-b.c1.example":        "a-b.c1.example",
	}
	for in, want := range cases {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestNormalizeRejectsNonHostnames(t *testing.T) {
	bad := []string{
		"", ".", "..", "../../tmp/x", "/srv/uploads/x", "example.com/path",
		"example.com\\evil", "https://example.com", "user@example.com",
		"example.com:8443", "127.0.0.1", "127.0.0.1:8443", "[::1]", "::1",
		"example.com?x=1", "example.com#frag", " example.com", "example.com ",
		"exa mple.com", "example..com", ".example.com", "-example.com",
		"example-.com", "exam_ple.com", "example.com..", "a%2eb", "\x00example.com",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("abcdefghij.", 26) + "example",
	}
	for _, in := range bad {
		if got, err := Normalize(in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", in, got)
		}
	}
}

func TestValidateHTTPSURLForDomain(t *testing.T) {
	if err := ValidateHTTPSURLForDomain("https://example.com/.well-known/agent-identity-revocations.json", "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateHTTPSURLForDomain("https://EXAMPLE.com/x", "example.com."); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		"http://example.com/x", "https://other.com/x", "https://example.com:8443/x",
		"https://user@example.com/x", "https://169.254.169.254/latest/meta-data/",
		"https://[::1]/x", "https://example.com/x#frag", "ftp://example.com/x", "not a url",
	}
	for _, in := range bad {
		if err := ValidateHTTPSURLForDomain(in, "example.com"); err == nil {
			t.Errorf("ValidateHTTPSURLForDomain(%q) accepted", in)
		}
	}
}
