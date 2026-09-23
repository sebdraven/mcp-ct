package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sebdraven/mcp-ct/internal/certspotter"
)

// issuance builds one record in the shape the API returns.
func issuance(id string, notBefore, notAfter time.Time, names ...string) map[string]any {
	return map[string]any{
		"id":         id,
		"dns_names":  names,
		"issuer":     map[string]any{"name": "C=US, O=Let's Encrypt, CN=R3"},
		"not_before": notBefore.Format(time.RFC3339),
		"not_after":  notAfter.Format(time.RFC3339),
	}
}

func newService(t *testing.T, issuances ...map[string]any) *Service {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if issuances == nil {
			fmt.Fprint(w, "[]")
			return
		}
		_ = json.NewEncoder(w).Encode(issuances)
	}))
	t.Cleanup(srv.Close)
	return New(certspotter.New("TOK",
		certspotter.WithBaseURL(srv.URL),
		certspotter.WithBackoff(time.Millisecond)))
}

func TestCertsSortsNewestFirst(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	svc := newService(t,
		issuance("1", now.AddDate(-3, 0, 0), now.AddDate(-3, 3, 0), "example.com"),
		issuance("2", now.AddDate(0, -1, 0), now.AddDate(0, 2, 0), "example.com"),
		issuance("3", now.AddDate(-1, 0, 0), now.AddDate(-1, 3, 0), "example.com"),
	)

	res, err := svc.Certs(context.Background(), "Example.com", false, true)
	if err != nil {
		t.Fatalf("Certs: %v", err)
	}
	if res.Domain != "example.com" {
		t.Errorf("Domain = %q, want it normalised", res.Domain)
	}
	if res.Total != 3 || len(res.Certificates) != 3 {
		t.Fatalf("Total = %d, got %d certificates", res.Total, len(res.Certificates))
	}
	for i := 1; i < len(res.Certificates); i++ {
		if res.Certificates[i-1].NotBefore.Before(res.Certificates[i].NotBefore) {
			t.Fatalf("not sorted by not_before descending: %v", res.Certificates)
		}
	}
	if res.Certificates[0].ID != "2" {
		t.Errorf("first id = %q, want the most recent issuance", res.Certificates[0].ID)
	}
}

func TestCertsIncludeExpired(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	build := func() *Service {
		return newService(t,
			issuance("old", now.AddDate(-3, 0, 0), now.AddDate(-3, 3, 0), "example.com"),
			issuance("live", now.AddDate(0, -1, 0), now.AddDate(0, 2, 0), "example.com"),
		)
	}

	all, err := build().Certs(context.Background(), "example.com", false, true)
	if err != nil {
		t.Fatalf("Certs: %v", err)
	}
	if all.Total != 2 {
		t.Errorf("include_expired=true kept %d, want 2", all.Total)
	}

	live, err := build().Certs(context.Background(), "example.com", false, false)
	if err != nil {
		t.Fatalf("Certs: %v", err)
	}
	if live.Total != 1 || live.Certificates[0].ID != "live" {
		t.Errorf("include_expired=false kept %d: %v", live.Total, live.Certificates)
	}
}

// certspotter is asked for the right scope, and the answer is filtered back to
// it: a name that is not the domain or one of its subdomains is dropped.
func TestCertsScope(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nb, na := now.AddDate(0, -1, 0), now.AddDate(0, 2, 0)

	svc := newService(t,
		issuance("apex", nb, na, "example.com"),
		issuance("sub", nb, na, "api.example.com"),
		issuance("other", nb, na, "notexample.com"),
	)
	exact, err := svc.Certs(context.Background(), "example.com", false, true)
	if err != nil {
		t.Fatalf("Certs: %v", err)
	}
	if exact.Total != 1 || exact.Certificates[0].ID != "apex" {
		t.Errorf("exact match kept %d: %v", exact.Total, exact.Certificates)
	}

	svc = newService(t,
		issuance("apex", nb, na, "example.com"),
		issuance("sub", nb, na, "api.example.com"),
		issuance("other", nb, na, "notexample.com"),
	)
	wide, err := svc.Certs(context.Background(), "example.com", true, true)
	if err != nil {
		t.Fatalf("Certs: %v", err)
	}
	if wide.Total != 2 {
		t.Errorf("subdomain match kept %d, want 2: %v", wide.Total, wide.Certificates)
	}
}

func TestLastSeenWindow(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	oldest := now.AddDate(-5, 0, 0)
	newest := now.AddDate(-2, 0, 0)

	svc := newService(t,
		issuance("1", oldest, oldest.AddDate(0, 3, 0), "example.com"),
		issuance("2", newest, newest.AddDate(0, 3, 0), "example.com"),
		issuance("3", now.AddDate(-4, 0, 0), now.AddDate(-4, 3, 0), "example.com"),
	)

	res, err := svc.LastSeen(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("LastSeen: %v", err)
	}
	if !res.Found {
		t.Fatal("Found is false with three certificates")
	}
	if res.TotalCertificates != 3 {
		t.Errorf("TotalCertificates = %d, want 3", res.TotalCertificates)
	}
	if !res.FirstSeen.Equal(oldest) {
		t.Errorf("FirstSeen = %v, want %v", res.FirstSeen, oldest)
	}
	if !res.LastSeen.Equal(newest) || !res.LastNotBefore.Equal(newest) {
		t.Errorf("LastSeen = %v, LastNotBefore = %v, want %v", res.LastSeen, res.LastNotBefore, newest)
	}
}

// An expired certificate is the whole point: a dead domain must still be dated.
func TestLastSeenCountsExpiredCertificates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nb := now.AddDate(-7, 0, 0)

	svc := newService(t, issuance("1", nb, nb.AddDate(0, 3, 0), "example.com"))
	res, err := svc.LastSeen(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("LastSeen: %v", err)
	}
	if !res.Found || res.TotalCertificates != 1 || !res.LastNotBefore.Equal(nb) {
		t.Errorf("a long-expired certificate was not counted: %+v", res)
	}
}

// Nothing logged is an answer, not an error, and it comes with what it means.
func TestEmptyResultIsNotAnError(t *testing.T) {
	svc := newService(t)

	certs, err := svc.Certs(context.Background(), "example.com", false, true)
	if err != nil {
		t.Fatalf("Certs: %v", err)
	}
	if certs.Total != 0 || certs.Certificates == nil {
		t.Errorf("Total = %d, Certificates = %v, want 0 and an empty list", certs.Total, certs.Certificates)
	}
	if !strings.Contains(certs.Note, "absence is not evidence") {
		t.Errorf("Note = %q, want the caveat about HTTP-only domains", certs.Note)
	}

	last, err := svc.LastSeen(context.Background(), "example.com", false)
	if err != nil {
		t.Fatalf("LastSeen: %v", err)
	}
	if last.Found || last.LastNotBefore != nil {
		t.Errorf("Found = %v, LastNotBefore = %v, want false and nil", last.Found, last.LastNotBefore)
	}
}

func TestBadDomainNeverReachesTheAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the API was called for an invalid domain")
	}))
	defer srv.Close()
	svc := New(certspotter.New("TOK", certspotter.WithBaseURL(srv.URL)))

	for _, bad := range []string{"", "   ", "localhost", "*.example.com"} {
		if _, err := svc.Certs(context.Background(), bad, false, true); err == nil {
			t.Errorf("Certs(%q) was accepted", bad)
		}
		if _, err := svc.LastSeen(context.Background(), bad, false); err == nil {
			t.Errorf("LastSeen(%q) was accepted", bad)
		}
	}
}

func TestQuotaExhaustionIsReportedNotSwallowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	svc := New(certspotter.New("TOK",
		certspotter.WithBaseURL(srv.URL),
		certspotter.WithBackoff(time.Millisecond)))

	res, err := svc.LastSeen(context.Background(), "example.com", false)
	if err == nil {
		t.Fatalf("a rate-limited lookup returned %+v instead of an error", res)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("err = %v, want it to name the rate limit", err)
	}
}
