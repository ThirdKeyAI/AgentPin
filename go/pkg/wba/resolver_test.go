package wba

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/weburl"
	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
)

// serve starts a server answering every request with handler and counts
// requests. It returns the directory URL.
func serve(t *testing.T, handler func(w http.ResponseWriter, url string)) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler(w, url)
	}))
	t.Cleanup(srv.Close)
	url = srv.URL + DirectoryPath
	return url, &hits
}

func respond(status int, headers []httpsig.Header, body []byte) func(http.ResponseWriter, string) {
	return func(w http.ResponseWriter, _ string) {
		for _, h := range headers {
			w.Header().Add(h.Name, h.Value)
		}
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

func localOpts() DirectoryFetchOptions {
	o := DefaultDirectoryFetchOptions()
	o.PublicOnly = false
	o.RequireHTTPS = false
	return o
}

func TestFetchesSignedDirectoryAndCachesIt(t *testing.T) {
	key := gen(t)
	body, _ := DirectoryFromKeys(key.PublicKey()).JSON()
	url, hits := serve(t, func(w http.ResponseWriter, url string) {
		u, _ := weburl.Parse(url)
		headers, err := SignDirectoryResponse(body, u.Authority(), []PrivateKey{key}, time.Now().Unix(), 3600)
		if err != nil {
			t.Error(err)
		}
		headers = append(headers,
			httpsig.Header{Name: "Content-Type", Value: DirectoryMediaType},
			httpsig.Header{Name: "Cache-Control", Value: "max-age=600"})
		respond(200, headers, body)(w, url)
	})

	opts := localOpts()
	opts.RequireProof = true
	dir, ttl, err := FetchDirectory(url, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(dir.Keys) != 1 || ttl != 600*time.Second {
		t.Fatalf("%d keys, ttl %v", len(dir.Keys), ttl)
	}

	r := NewCachingDirectoryResolver(localOpts())
	tp := Thumbprint(key.PublicKey())
	hits.Store(0)
	for i := 0; i < 2; i++ {
		k, found, err := r.Lookup(url, tp)
		if err != nil || !found || !k.Equal(key.PublicKey()) {
			t.Fatalf("lookup %d: %v %v", i, found, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("%d fetches; second lookup should be cached", hits.Load())
	}
	// A key the directory does not publish: resolved, not found.
	if _, found, err := r.Lookup(url, Thumbprint(gen(t).PublicKey())); err != nil || found {
		t.Fatalf("unknown key: %v %v", found, err)
	}
}

// A failed refetch keeps the cached directory instead of evicting it.
func TestFailedFetchKeepsCachedDirectory(t *testing.T) {
	key := gen(t)
	tp := Thumbprint(key.PublicKey())
	url := "http://127.0.0.1:9/.well-known/http-message-signatures-directory"
	r := NewCachingDirectoryResolver(localOpts())
	r.cache[url] = cachedDirectory{dir: DirectoryFromKeys(key.PublicKey()), freshUntil: time.Now()}
	if k, found, err := r.Lookup(url, tp); err != nil || !found || !k.Equal(key.PublicKey()) {
		t.Fatalf("stale fallback: %v %v", found, err)
	}
	if _, _, err := NewCachingDirectoryResolver(localOpts()).Lookup(url, tp); err == nil {
		t.Fatal("empty cache must report the fetch error")
	}
}

func TestRefusesUnsafeDirectories(t *testing.T) {
	body := []byte(`{"keys":[]}`)

	url, _ := serve(t, respond(302, []httpsig.Header{{Name: "Location", Value: "http://127.0.0.1:9/"}}, body))
	if _, _, err := FetchDirectory(url, localOpts()); err == nil {
		t.Fatal("redirect followed")
	}
	url, _ = serve(t, respond(404, nil, body))
	if _, _, err := FetchDirectory(url, localOpts()); err == nil {
		t.Fatal("404 accepted")
	}
	url, _ = serve(t, respond(204, nil, nil))
	if _, _, err := FetchDirectory(url, localOpts()); err == nil {
		t.Fatal("204 accepted")
	}
	big := []byte(`{"keys":[],"pad":"` + strings.Repeat("x", 70*1024) + `"}`)
	url, _ = serve(t, respond(200, nil, big))
	if _, _, err := FetchDirectory(url, localOpts()); err == nil {
		t.Fatal("oversized body accepted")
	}
	url, _ = serve(t, func(w http.ResponseWriter, _ string) {
		w.Header().Set("Transfer-Encoding", "chunked") // no Content-Length
		w.WriteHeader(200)
		for i := 0; i < 70; i++ {
			_, _ = w.Write([]byte(strings.Repeat("y", 1024)))
		}
	})
	if _, _, err := FetchDirectory(url, localOpts()); err == nil {
		t.Fatal("oversized streamed body accepted")
	}

	// Default options: http and loopback are refused before connecting.
	url, hits := serve(t, respond(200, nil, body))
	if _, _, err := FetchDirectory(url, DefaultDirectoryFetchOptions()); err == nil {
		t.Fatal("http accepted by default")
	}
	httpOK := DefaultDirectoryFetchOptions()
	httpOK.RequireHTTPS = false
	if _, _, err := FetchDirectory(url, httpOK); err == nil {
		t.Fatal("loopback accepted with PublicOnly")
	}
	// A hostname resolving to loopback is refused at dial time.
	if _, _, err := FetchDirectory(strings.Replace(url, "127.0.0.1", "localhost", 1), httpOK); err == nil {
		t.Fatal("localhost accepted with PublicOnly")
	}
	if hits.Load() != 0 {
		t.Fatalf("%d requests reached a refused server", hits.Load())
	}

	// RequireProof drops unsigned keys.
	key := gen(t)
	signedBody, _ := DirectoryFromKeys(key.PublicKey()).JSON()
	url, _ = serve(t, respond(200, []httpsig.Header{{Name: "Content-Digest", Value: httpsig.ContentDigest(signedBody)}}, signedBody))
	opts := localOpts()
	opts.RequireProof = true
	dir, _, err := FetchDirectory(url, opts)
	if err != nil || len(dir.Keys) != 0 {
		t.Fatalf("%v %v", dir, err)
	}
}

type fixedLookup struct {
	key   PublicKey
	found bool
}

func (f fixedLookup) Lookup(string, string) (PublicKey, bool, error) { return f.key, f.found, nil }

func TestVerifyWithCustomLookup(t *testing.T) {
	key := gen(t)
	req := newReq(t, "GET", "https://origin.example/")
	h, err := SignRequest(req, key, "https://agent.example/.well-known/http-message-signatures-directory", DefaultSignOptions())
	if err != nil {
		t.Fatal(err)
	}
	h.Apply(req)
	opts := DefaultVerifyOptions()
	expect(t, VerifyRequest(req, fixedLookup{key.PublicKey(), true}, opts), Verified)
	expect(t, VerifyRequest(req, fixedLookup{}, opts), Unverified)
	expect(t, VerifyRequest(req, fixedLookup{gen(t).PublicKey(), true}, opts), Invalid)
}

func TestParsesMaxAge(t *testing.T) {
	if n, ok := maxAge([]httpsig.Header{{Name: "Cache-Control", Value: "public, max-age=120"}}); !ok || n != 120 {
		t.Fatal(n, ok)
	}
	if _, ok := maxAge(nil); ok {
		t.Fatal("max-age from nothing")
	}
}

func TestTTLClamped(t *testing.T) {
	for cc, want := range map[string]time.Duration{
		"max-age=1": time.Minute, "max-age=999999999": 24 * time.Hour, "no-cache": time.Hour,
	} {
		key := gen(t)
		body, _ := DirectoryFromKeys(key.PublicKey()).JSON()
		url, _ := serve(t, respond(200, []httpsig.Header{{Name: "Cache-Control", Value: cc}}, body))
		_, ttl, err := FetchDirectory(url, localOpts())
		if err != nil || ttl != want {
			t.Errorf("%s: ttl %v, %v; want %v", cc, ttl, err, want)
		}
	}
}
