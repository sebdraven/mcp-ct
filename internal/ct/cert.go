// Package ct holds the shape a certspotter issuance is normalised to, and the
// domain handling shared by the layers above it.
package ct

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Certificate is one issuance seen in Certificate Transparency.
//
// The times are held in UTC, so they marshal as RFC 3339 with a Z whatever zone
// the API reported them in.
type Certificate struct {
	ID        string    `json:"id"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// UserAgent identifies this server to certspotter, which asks for something
// contactable rather than the bare Go default.
func UserAgent(version string) string {
	return "mcp-ct/" + version + " (+https://github.com/sebdraven/mcp-ct)"
}

// NormalizeDomain lowercases a domain and strips the root dot, rejecting the
// inputs the API would answer nonsense for — a URL, a bare label, whitespace.
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("a domain is required")
	}
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	d, _, _ = strings.Cut(d, "/")
	if h, _, found := strings.Cut(d, ":"); found {
		d = h
	}
	if strings.ContainsAny(d, " \t\n*") {
		return "", fmt.Errorf("%q is not a domain", s)
	}
	if !strings.Contains(d, ".") {
		return "", fmt.Errorf("%q is not a domain: a registrable name needs at least one dot", s)
	}
	return d, nil
}

// InScope reports whether any name on a certificate is the domain itself, or
// one of its subdomains when asked. A wildcard needs no special case: the
// "*.example.com" form is a subdomain match by suffix.
func InScope(names []string, domain string, includeSubdomains bool) bool {
	for _, n := range names {
		n = strings.Trim(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == domain {
			return true
		}
		if includeSubdomains && strings.HasSuffix(n, "."+domain) {
			return true
		}
	}
	return false
}

// SortByNotBeforeDesc puts the most recent issuance first. Ties break on id so
// a repeated call over unchanged data returns an unchanged list.
func SortByNotBeforeDesc(certs []Certificate) {
	sort.SliceStable(certs, func(i, j int) bool {
		if certs[i].NotBefore.Equal(certs[j].NotBefore) {
			return certs[i].ID > certs[j].ID
		}
		return certs[i].NotBefore.After(certs[j].NotBefore)
	})
}

// NormalizeNames lowercases the SANs and drops the blanks and repeats a
// certificate can carry.
func NormalizeNames(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.Trim(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}
