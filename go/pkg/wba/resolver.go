package wba

import (
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ThirdKeyAi/agentpin/go/internal/weburl"
	"github.com/ThirdKeyAi/agentpin/go/pkg/fetch"
	"github.com/ThirdKeyAi/agentpin/go/pkg/httpsig"
)

// DirectoryFetchOptions configures directory fetching. The
// Signature-Agent URL comes from the client, so every fetch is hardened
// against SSRF (draft §6.7): https only, no redirects, non-public
// addresses refused, bounded time, bytes and key count.
type DirectoryFetchOptions struct {
	// Timeout bounds one fetch (default 10 s).
	Timeout time.Duration
	// MaxBytes caps the response body (default 64 KiB).
	MaxBytes int64
	// PublicOnly refuses hosts that are or resolve to non-public addresses
	// (default true). Only disable for tests against local servers.
	PublicOnly bool
	// RequireHTTPS requires https URLs (default true). Only disable for
	// tests.
	RequireHTTPS bool
	// RequireProof keeps only keys with a valid directory response
	// signature (Appendix B.1). Default false: a directory the verifier
	// resolved itself is usable without proof.
	RequireProof bool
	// DefaultTTL is the cache lifetime when the response has no usable
	// max-age; MinTTL and MaxTTL bound max-age.
	DefaultTTL, MinTTL, MaxTTL time.Duration
}

// DefaultDirectoryFetchOptions returns the hardened defaults.
func DefaultDirectoryFetchOptions() DirectoryFetchOptions {
	return DirectoryFetchOptions{
		Timeout:      fetch.DefaultTimeout,
		MaxBytes:     64 * 1024,
		PublicOnly:   true,
		RequireHTTPS: true,
		DefaultTTL:   time.Hour,
		MinTTL:       time.Minute,
		MaxTTL:       24 * time.Hour,
	}
}

func maxAge(headers []httpsig.Header) (int64, bool) {
	cc, ok := httpsig.CombinedField(headers, "cache-control")
	if !ok {
		return 0, false
	}
	for _, d := range strings.Split(cc, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(d), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "max-age") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(v), "+"), 10, 64)
		if err == nil {
			if n > 1<<62 {
				n = 1 << 62
			}
			return int64(n), true
		}
	}
	return 0, false
}

// FetchDirectory fetches and parses the key directory at rawURL. It
// returns the directory and how long it may be cached.
func FetchDirectory(rawURL string, opts DirectoryFetchOptions) (*Directory, time.Duration, error) {
	u, err := weburl.Parse(rawURL)
	if err != nil {
		return nil, 0, wbaErr("invalid directory URL")
	}
	if opts.RequireHTTPS && u.Scheme != "https" {
		return nil, 0, wbaErr("directory %s is not https", rawURL)
	}
	resp, err := fetch.Bounded(rawURL, fetch.BoundedOptions{
		Timeout:    opts.Timeout,
		MaxBytes:   opts.MaxBytes,
		PublicOnly: opts.PublicOnly,
		Accept:     DirectoryMediaType + ", application/jwk-set+json, application/json",
	})
	if err != nil {
		return nil, 0, err
	}
	if resp.Status != 200 {
		return nil, 0, wbaErr("HTTP %d fetching %s", resp.Status, rawURL)
	}
	headers := make([]httpsig.Header, len(resp.Headers))
	for i, h := range resp.Headers {
		headers[i] = httpsig.Header{Name: h[0], Value: h[1]}
	}
	var dir *Directory
	if opts.RequireProof {
		dir, err = VerifyDirectoryResponse(resp.Body, headers, u.Authority(), time.Now().Unix(), 60)
	} else {
		dir, err = ParseDirectory(resp.Body)
	}
	if err != nil {
		return nil, 0, err
	}
	ttl := opts.DefaultTTL
	if secs, ok := maxAge(headers); ok {
		ttl = time.Duration(min(secs, int64(opts.MaxTTL/time.Second)+1)) * time.Second
	}
	ttl = max(opts.MinTTL, min(ttl, opts.MaxTTL))
	return dir, ttl, nil
}

type cachedDirectory struct {
	dir        *Directory
	freshUntil time.Time
}

// CachingDirectoryResolver is a KeyLookup that fetches directories on
// demand and caches them per URL. A resolved directory replaces the cached
// copy; a failed fetch never evicts it, so a directory outage does not
// revoke an agent's keys (§6.10). Safe for concurrent use.
type CachingDirectoryResolver struct {
	opts  DirectoryFetchOptions
	mu    sync.Mutex
	cache map[string]cachedDirectory
}

// NewCachingDirectoryResolver returns a resolver using opts.
func NewCachingDirectoryResolver(opts DirectoryFetchOptions) *CachingDirectoryResolver {
	return &CachingDirectoryResolver{opts: opts, cache: map[string]cachedDirectory{}}
}

func (r *CachingDirectoryResolver) cached(u string, freshOnly bool) *Directory {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.cache[u]
	if !ok || (freshOnly && !c.freshUntil.After(time.Now())) {
		return nil
	}
	return c.dir
}

// Lookup implements KeyLookup.
func (r *CachingDirectoryResolver) Lookup(signatureAgent, keyid string) (PublicKey, bool, error) {
	// Verified requests always pass a normalized https URL; plain URLs are
	// only reachable with RequireHTTPS off (tests).
	u := signatureAgent
	if r.opts.RequireHTTPS {
		n, err := NormalizeSignatureAgent(signatureAgent)
		if err != nil {
			return PublicKey{}, false, err
		}
		u = n
	}
	now := time.Now().Unix()
	if d := r.cached(u, true); d != nil {
		if k, ok := FindKey(d, keyid, now, 60); ok {
			return k, true, nil
		}
	}
	dir, ttl, err := FetchDirectory(u, r.opts)
	if err != nil {
		// A failed fetch is not evidence: fall back to the last resolved
		// copy (§6.10).
		if d := r.cached(u, false); d != nil {
			k, ok := FindKey(d, keyid, now, 60)
			return k, ok, nil
		}
		return PublicKey{}, false, err
	}
	r.mu.Lock()
	r.cache[u] = cachedDirectory{dir: dir, freshUntil: time.Now().Add(ttl)}
	r.mu.Unlock()
	k, ok := FindKey(dir, keyid, now, 60)
	return k, ok, nil
}
