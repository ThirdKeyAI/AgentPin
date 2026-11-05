package weburl

import "testing"

func TestParseSerializesLikeWHATWG(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com":                     "https://example.com/",
		"HTTPS://Example.COM:443/a/./b/../c?x#f":  "https://example.com/a/c?x#f",
		"http://example.com:80/":                  "http://example.com/",
		"https://example.com:08443/p":             "https://example.com:8443/p",
		"https://example.com/a b?c d#e f":         "https://example.com/a%20b?c%20d#e%20f",
		"https://example.com/%7e/../x/..":         "https://example.com/",
		"https://example.com/?":                   "https://example.com/?",
		"https://[::0:1]:8443/":                   "https://[::1]:8443/",
		"https://bücher.example/":                 "https://xn--bcher-kva.example/",
		"https://user:pw@example.com/":            "https://user:pw@example.com/",
		"https://@example.com/":                   "https://example.com/",
		"https://example.com/a/%2e%2E/b/.%2e/c/.": "https://example.com/c/",
	} {
		u, err := Parse(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := u.String(); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"/relative", "mailto:a@b.test", "https://", "https://example.com:99999/", "https:example.com"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
