// Package fetch is the hardened HTTP layer shared by every network resolver.
//
// Every outbound request made by the SDK goes through JSONBounded, which
// enforces the network defaults the spec and the security review require
// (AP-7, AP-12, AP-13): redirects are never followed, a request timeout
// bounds stalls, the response body is capped both by Content-Length and
// while streaming, the response must carry a JSON Content-Type, and error
// strings are generic (URL and failure class, never transport detail).
package fetch

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultTimeout bounds a single request.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxBytes caps the accepted response body (1 MiB).
	DefaultMaxBytes int64 = 1 << 20
)

// DefaultClient returns a client with the default timeout that never
// follows redirects.
func DefaultClient() *http.Client {
	return &http.Client{
		Timeout: DefaultTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func isJSONContentType(value string) bool {
	media, _, err := mime.ParseMediaType(value)
	if err != nil {
		media = strings.ToLower(strings.TrimSpace(strings.Split(value, ";")[0]))
	}
	media = strings.ToLower(media)
	return media == "application/json" || strings.HasSuffix(media, "+json")
}

// JSONBounded GETs url with client (DefaultClient when nil) and returns the
// body, or found=false on HTTP 404. Rejects redirects, non-success
// statuses, non-JSON content types and bodies larger than maxBytes
// (DefaultMaxBytes when <= 0). The client's redirect policy is always
// overridden so redirects are reported rather than followed.
func JSONBounded(client *http.Client, url string, maxBytes int64) (body []byte, found bool, err error) {
	if client == nil {
		client = DefaultClient()
	} else {
		c := *client
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		if c.Timeout == 0 {
			c.Timeout = DefaultTimeout
		}
		client = &c
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, errors.New("invalid URL")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch %s", url)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, false, fmt.Errorf("redirect rejected fetching %s (status %d)", url, resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("HTTP %d fetching %s", resp.StatusCode, url)
	}
	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil, false, fmt.Errorf("response from %s is not application/json", url)
	}
	if resp.ContentLength > maxBytes {
		return nil, false, fmt.Errorf("response from %s exceeds %d bytes", url, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("failed to read response from %s", url)
	}
	if int64(len(data)) > maxBytes {
		return nil, false, fmt.Errorf("response from %s exceeds %d bytes", url, maxBytes)
	}
	return data, true, nil
}
