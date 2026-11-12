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
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
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

// IsNonPublic reports whether ip is an address a server-side fetch driven
// by a client-supplied URL must never reach: loopback, private,
// link-local, CGNAT, multicast, documentation, unspecified and reserved
// ranges.
func IsNonPublic(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		o := v4
		return v4.IsLoopback() || v4.IsPrivate() || v4.IsLinkLocalUnicast() ||
			v4.IsUnspecified() || v4.IsMulticast() ||
			o[0] == 0 ||
			(o[0] == 100 && o[1]&0xc0 == 64) ||
			(o[0] == 192 && o[1] == 0 && o[2] == 0) ||
			(o[0] == 192 && o[1] == 0 && o[2] == 2) ||
			(o[0] == 198 && o[1]&0xfe == 18) ||
			(o[0] == 198 && o[1] == 51 && o[2] == 100) ||
			(o[0] == 203 && o[1] == 0 && o[2] == 113) ||
			o[0] >= 240
	}
	if len(ip) != net.IPv6len {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip[0]&0xfe == 0xfc ||
		(ip[0] == 0xfe && ip[1]&0xc0 == 0x80) ||
		(ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8) ||
		(ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b)
}

// BoundedOptions configures Bounded.
type BoundedOptions struct {
	// Timeout bounds the whole request (DefaultTimeout when 0).
	Timeout time.Duration
	// MaxBytes caps the response body (DefaultMaxBytes when <= 0).
	MaxBytes int64
	// PublicOnly refuses hosts that are, or resolve to, non-public
	// addresses. The check runs on the address actually dialed, so DNS
	// rebinding cannot bypass it, and proxies are disabled.
	PublicOnly bool
	// Accept is the Accept header value.
	Accept string
}

// Response is a response read by Bounded.
type Response struct {
	Status int
	// Headers as (name, value) pairs; names in canonical form.
	Headers [][2]string
	Body    []byte
}

func refuseNonPublic(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || IsNonPublic(ip) {
		return errors.New("refusing to connect to a non-public address")
	}
	return nil
}

// Bounded GETs rawURL with the same limits as JSONBounded (no redirects,
// timeout, byte cap) and returns status, headers and body for any
// non-redirect status.
func Bounded(rawURL string, opts BoundedOptions) (*Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid URL %s", rawURL)
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.PublicOnly {
		if ip := net.ParseIP(u.Hostname()); ip != nil && IsNonPublic(ip) {
			return nil, fmt.Errorf("refusing to fetch non-public address %s", rawURL)
		}
		dialer := &net.Dialer{Timeout: opts.Timeout, Control: refuseNonPublic}
		transport.DialContext = dialer.DialContext
		transport.Proxy = nil
	}
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %s", rawURL)
	}
	if opts.Accept != "" {
		req.Header.Set("Accept", opts.Accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s", rawURL)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("redirect rejected fetching %s (status %d)", rawURL, resp.StatusCode)
	}
	if resp.ContentLength > opts.MaxBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", rawURL, opts.MaxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read response from %s", rawURL)
	}
	if int64(len(body)) > opts.MaxBytes {
		return nil, fmt.Errorf("response from %s exceeds %d bytes", rawURL, opts.MaxBytes)
	}
	out := &Response{Status: resp.StatusCode, Body: body}
	for name, values := range resp.Header {
		for _, v := range values {
			out.Headers = append(out.Headers, [2]string{name, v})
		}
	}
	return out, nil
}
