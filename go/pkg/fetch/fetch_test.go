package fetch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func serve(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestFetchesSmallJSON(t *testing.T) {
	s := serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"a":1}`))
	})
	defer s.Close()
	body, found, err := JSONBounded(nil, s.URL+"/doc.json", 0)
	if err != nil || !found || string(body) != `{"a":1}` {
		t.Fatalf("body=%s found=%v err=%v", body, found, err)
	}
}

// AP-7 / AP-12: redirects are rejected, never followed — even when the
// caller supplies a client that would follow them.
func TestRejectsRedirect(t *testing.T) {
	target := serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"evil":true}`))
	})
	defer target.Close()
	s := serve(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	})
	defer s.Close()
	for _, c := range []*http.Client{nil, {}} {
		_, _, err := JSONBounded(c, s.URL+"/doc.json", 0)
		if err == nil || !strings.Contains(err.Error(), "redirect rejected") {
			t.Fatalf("expected redirect rejection, got %v", err)
		}
	}
}

// AP-13: oversized bodies are rejected by Content-Length and while streaming.
func TestRejectsOversizedBody(t *testing.T) {
	big := strings.Repeat(" ", 2048)
	s := serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(big))
	})
	defer s.Close()
	if _, _, err := JSONBounded(nil, s.URL, 1024); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("content-length cap: %v", err)
	}
	chunked := serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fl, _ := w.(http.Flusher)
		for i := 0; i < 4; i++ {
			_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
			if fl != nil {
				fl.Flush()
			}
		}
	})
	defer chunked.Close()
	if _, _, err := JSONBounded(nil, chunked.URL, 1024); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("streaming cap: %v", err)
	}
}

// AP-13: non-JSON content types are rejected.
func TestRejectsNonJSONContentType(t *testing.T) {
	s := serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`{}`))
	})
	defer s.Close()
	if _, _, err := JSONBounded(nil, s.URL, 0); err == nil || !strings.Contains(err.Error(), "not application/json") {
		t.Fatalf("content type: %v", err)
	}
}

// AP-13: a stalled server times out.
func TestTimesOut(t *testing.T) {
	s := serve(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	})
	defer s.Close()
	start := time.Now()
	_, _, err := JSONBounded(&http.Client{Timeout: 200 * time.Millisecond}, s.URL, 0)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestNotFoundIsNotFound(t *testing.T) {
	s := serve(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer s.Close()
	_, found, err := JSONBounded(nil, s.URL, 0)
	if err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

// Error strings never carry transport-level detail.
func TestConnectionErrorsAreGeneric(t *testing.T) {
	s := serve(func(w http.ResponseWriter, r *http.Request) {})
	url := s.URL + "/doc.json"
	s.Close()
	_, _, err := JSONBounded(nil, url, 0)
	if err == nil || err.Error() != "failed to fetch "+url {
		t.Fatalf("got %v", err)
	}
}
