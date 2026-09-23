package ct

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"Example.COM":               "example.com",
		" example.com. ":            "example.com",
		"https://example.com/a/b":   "example.com",
		"http://example.com:8443/":  "example.com",
		"sub.example.co.uk":         "sub.example.co.uk",
		"xn--80ak6aa92e.com":        "xn--80ak6aa92e.com",
		"HTTPS://Example.com:443/x": "example.com",
	}
	for in, want := range ok {
		got, err := NormalizeDomain(in)
		if err != nil {
			t.Errorf("NormalizeDomain(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"", "   ", "localhost", "*.example.com", "exa mple.com"} {
		if got, err := NormalizeDomain(bad); err == nil {
			t.Errorf("NormalizeDomain(%q) = %q, want an error", bad, got)
		}
	}
}

func TestInScope(t *testing.T) {
	names := []string{"WWW.Example.com", "api.example.com."}

	if !InScope(names, "www.example.com", false) {
		t.Error("an exact name, differently cased, was not in scope")
	}
	if InScope(names, "example.com", false) {
		t.Error("a subdomain matched an exact-only query")
	}
	if !InScope(names, "example.com", true) {
		t.Error("a subdomain did not match a subdomain query")
	}
	// The suffix check covers wildcards without a special case.
	if !InScope([]string{"*.example.com"}, "example.com", true) {
		t.Error("a wildcard name did not match a subdomain query")
	}
	// evilexample.com must not match example.com on a bare suffix.
	if InScope([]string{"evilexample.com"}, "example.com", true) {
		t.Error("a name merely ending in the domain was treated as a subdomain")
	}
}

func TestNormalizeNamesDropsBlanksAndDuplicates(t *testing.T) {
	got := NormalizeNames([]string{"example.com", " WWW.example.com ", "", "example.com.", "*.example.com"})
	want := []string{"example.com", "www.example.com", "*.example.com"}
	if len(got) != len(want) {
		t.Fatalf("NormalizeNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NormalizeNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSortByNotBeforeDescIsStableOnTies(t *testing.T) {
	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	certs := []Certificate{
		{ID: "1", NotBefore: at.AddDate(0, 0, -10)},
		{ID: "2", NotBefore: at},
		{ID: "3", NotBefore: at},
	}
	SortByNotBeforeDesc(certs)
	if certs[0].ID != "3" || certs[1].ID != "2" || certs[2].ID != "1" {
		t.Errorf("order = %q %q %q", certs[0].ID, certs[1].ID, certs[2].ID)
	}
}

// Whatever a source called it, a timestamp leaves here as RFC 3339 in UTC.
func TestCertificateMarshalsTimesAsUTC(t *testing.T) {
	paris := time.FixedZone("CET", 3600)
	c := Certificate{
		ID:        "42",
		NotBefore: time.Date(2026, 1, 2, 4, 0, 0, 0, paris).UTC(),
		NotAfter:  time.Date(2026, 4, 2, 4, 0, 0, 0, paris).UTC(),
	}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"not_before":"2026-01-02T03:00:00Z"`) {
		t.Errorf("not_before did not marshal as UTC: %s", b)
	}
}
