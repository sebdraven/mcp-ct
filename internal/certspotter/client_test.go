package certspotter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const oneIssuance = `[{
  "id": "5910248",
  "dns_names": ["example.com", "www.example.com"],
  "issuer": {"name": "C=US, O=Let's Encrypt, CN=R3"},
  "not_before": "2026-01-02T03:04:05+01:00",
  "not_after": "2026-04-02T03:04:05+01:00"
}]`

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New("TOK", WithBaseURL(srv.URL), WithBackoff(time.Millisecond))
}

func TestIssuancesSendsTokenAndExpansions(t *testing.T) {
	var got struct {
		auth       string
		agent      string
		path       string
		domain     string
		subdomains string
		limit      string
		expand     []string
	}
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		got.auth = r.Header.Get("Authorization")
		got.agent = r.Header.Get("User-Agent")
		got.path = r.URL.Path
		got.domain = q.Get("domain")
		got.subdomains = q.Get("include_subdomains")
		got.limit = q.Get("limit")
		got.expand = q["expand"]
		fmt.Fprint(w, oneIssuance)
	})

	certs, truncated, err := c.Issuances(context.Background(), "example.com", true)
	if err != nil {
		t.Fatalf("Issuances: %v", err)
	}
	if truncated {
		t.Error("a single short page was reported truncated")
	}
	if got.auth != "Bearer TOK" {
		t.Errorf("Authorization = %q, want the Bearer scheme", got.auth)
	}
	if got.agent == "" || strings.HasPrefix(got.agent, "Go-http-client") {
		t.Errorf("User-Agent = %q, want an explicit one", got.agent)
	}
	if got.path != "/v1/issuances" {
		t.Errorf("path = %q", got.path)
	}
	if got.domain != "example.com" || got.subdomains != "true" {
		t.Errorf("domain = %q, include_subdomains = %q", got.domain, got.subdomains)
	}
	if got.limit != fmt.Sprint(pageLimit) {
		t.Errorf("limit = %q, want the API maximum %d", got.limit, pageLimit)
	}
	if len(got.expand) != 3 {
		t.Errorf("expand = %v, want dns_names, issuer and cert", got.expand)
	}

	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
	// +01:00 in, UTC out.
	if w := "2026-01-02T02:04:05Z"; certs[0].NotBefore.Format(time.RFC3339) != w {
		t.Errorf("NotBefore = %s, want %s", certs[0].NotBefore.Format(time.RFC3339), w)
	}
	if certs[0].Issuer != "C=US, O=Let's Encrypt, CN=R3" {
		t.Errorf("Issuer = %q", certs[0].Issuer)
	}
	if len(certs[0].DNSNames) != 2 {
		t.Errorf("DNSNames = %v", certs[0].DNSNames)
	}
}

// A full page means there may be more; the next request continues from the last
// id, and an issuance seen in two logs is kept once.
func TestIssuancesPaginatesAndDeduplicates(t *testing.T) {
	var afters []string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		after := r.URL.Query().Get("after")
		afters = append(afters, after)

		page := make([]map[string]any, 0, pageLimit)
		if after == "" {
			for i := range pageLimit {
				// The last two entries repeat id 500, as two logs of one cert do.
				id := i
				if i == pageLimit-1 {
					id = 500
				}
				page = append(page, issuanceJSON(id))
			}
		} else {
			page = append(page, issuanceJSON(pageLimit))
		}
		_ = json.NewEncoder(w).Encode(page)
	})

	certs, truncated, err := c.Issuances(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("Issuances: %v", err)
	}
	if truncated {
		t.Error("truncated on a two-page result")
	}
	if len(afters) != 2 {
		t.Fatalf("made %d requests, want 2", len(afters))
	}
	if afters[0] != "" || afters[1] != "500" {
		t.Errorf("after = %q then %q, want empty then the last id seen", afters[0], afters[1])
	}
	// 1000 in the first page minus the one repeat, plus 1 in the second.
	if want := pageLimit; len(certs) != want {
		t.Errorf("got %d certificates, want %d after dedup", len(certs), want)
	}
}

func issuanceJSON(id int) map[string]any {
	return map[string]any{
		"id":         fmt.Sprint(id),
		"dns_names":  []string{"example.com"},
		"issuer":     map[string]any{"name": "CN=R3"},
		"not_before": "2026-01-02T03:04:05Z",
		"not_after":  "2026-04-02T03:04:05Z",
	}
}

func TestRateLimitIsRetriedThenReportedUnavailable(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "0")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	})

	_, _, err := c.Issuances(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("a 429 on every attempt succeeded")
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want it to satisfy ErrUnavailable so the caller falls back", err)
	}
	if calls != maxAttempts {
		t.Errorf("made %d attempts, want %d", calls, maxAttempts)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error does not name the status: %v", err)
	}
}

func TestServerErrorIsRetried(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls++; calls < 3 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, oneIssuance)
	})

	certs, _, err := c.Issuances(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("Issuances: %v", err)
	}
	if len(certs) != 1 {
		t.Errorf("got %d certificates after a retry, want 1", len(certs))
	}
}

// A rejected token is worth falling back for, but not worth retrying: it will
// not become valid on the second attempt.
func TestRejectedTokenFailsFastAndFallsBack(t *testing.T) {
	var calls int
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "nope", http.StatusUnauthorized)
	})

	_, _, err := c.Issuances(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("a 401 succeeded")
	}
	if calls != 1 {
		t.Errorf("made %d attempts on a 401, want 1", calls)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Errorf("err = %v, want it to satisfy ErrUnavailable", err)
	}
	if !strings.Contains(err.Error(), "CERTSPOTTER_TOKEN") {
		t.Errorf("error does not say what to check: %v", err)
	}
}

// A malformed request is ours to fix; answering it from crt.sh would hide it.
func TestBadRequestIsNotUnavailable(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad domain", http.StatusBadRequest)
	})

	_, _, err := c.Issuances(context.Background(), "example.com", false)
	if err == nil {
		t.Fatal("a 400 succeeded")
	}
	if errors.Is(err, ErrUnavailable) {
		t.Errorf("a 400 was treated as unavailable: %v", err)
	}
}

func TestNoTokenSendsNoAuthorizationHeader(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		fmt.Fprint(w, oneIssuance)
	}))
	defer srv.Close()

	c := New("", WithBaseURL(srv.URL), WithBackoff(time.Millisecond))
	if c.HasToken() {
		t.Error("HasToken is true with no token")
	}
	if _, _, err := c.Issuances(context.Background(), "example.com", false); err != nil {
		t.Fatalf("Issuances: %v", err)
	}
	if auth != "" {
		t.Errorf("Authorization = %q, want none", auth)
	}
}

func TestRetryAfterHeader(t *testing.T) {
	if got := retryAfter("12"); got != 12*time.Second {
		t.Errorf("retryAfter(\"12\") = %v", got)
	}
	if got := retryAfter(""); got != 0 {
		t.Errorf("retryAfter(\"\") = %v", got)
	}
	if got := retryAfter("not a date"); got != 0 {
		t.Errorf("retryAfter(garbage) = %v", got)
	}
	future := time.Now().UTC().Add(30 * time.Second).Format(http.TimeFormat)
	if got := retryAfter(future); got <= 0 {
		t.Errorf("retryAfter(HTTP-date) = %v, want a positive delay", got)
	}
}

func TestContextCancellationStopsPaging(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		cancel()
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	if _, _, err := c.Issuances(ctx, "example.com", false); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}
