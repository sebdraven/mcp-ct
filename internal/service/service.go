// Package service turns the certspotter index into the questions an analyst
// asks: which certificates has this domain had, and when was the last one
// issued.
package service

import (
	"context"
	"strings"
	"time"

	"github.com/sebdraven/mcp-ct/internal/certspotter"
	"github.com/sebdraven/mcp-ct/internal/ct"
)

type Service struct {
	client *certspotter.Client
}

func New(c *certspotter.Client) *Service {
	return &Service{client: c}
}

type CertsResult struct {
	Domain            string           `json:"domain"`
	IncludeSubdomains bool             `json:"include_subdomains"`
	IncludeExpired    bool             `json:"include_expired"`
	FetchedAt         string           `json:"fetched_at"`
	Total             int              `json:"total"`
	Certificates      []ct.Certificate `json:"certificates"`
	Note              string           `json:"note,omitempty"`
}

type LastSeenResult struct {
	Domain            string     `json:"domain"`
	IncludeSubdomains bool       `json:"include_subdomains"`
	FetchedAt         string     `json:"fetched_at"`
	Found             bool       `json:"found"`
	LastNotBefore     *time.Time `json:"last_not_before,omitempty"`
	TotalCertificates int        `json:"total_certificates"`
	FirstSeen         *time.Time `json:"first_seen,omitempty"`
	LastSeen          *time.Time `json:"last_seen,omitempty"`
	Note              string     `json:"note,omitempty"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Certs lists every certificate seen for a domain, newest first.
func (s *Service) Certs(ctx context.Context, domain string, includeSubdomains, includeExpired bool) (CertsResult, error) {
	d, err := ct.NormalizeDomain(domain)
	if err != nil {
		return CertsResult{}, err
	}

	certs, note, err := s.fetch(ctx, d, includeSubdomains)
	if err != nil {
		return CertsResult{}, err
	}

	if !includeExpired {
		certs = notExpired(certs, time.Now().UTC())
	}
	ct.SortByNotBeforeDesc(certs)

	res := CertsResult{
		Domain:            d,
		IncludeSubdomains: includeSubdomains,
		IncludeExpired:    includeExpired,
		FetchedAt:         now(),
		Total:             len(certs),
		Certificates:      certs,
		Note:              note,
	}
	if len(certs) == 0 {
		res.Certificates = []ct.Certificate{}
		res.Note = join(note, emptyNote(d))
	}
	return res, nil
}

// LastSeen dates a domain from its certificates: when the most recent one was
// issued, and the window the whole set spans.
//
// Expired certificates are deliberately kept. They are the evidence — a domain
// whose last certificate expired in 2019 is exactly the answer being looked
// for.
func (s *Service) LastSeen(ctx context.Context, domain string, includeSubdomains bool) (LastSeenResult, error) {
	d, err := ct.NormalizeDomain(domain)
	if err != nil {
		return LastSeenResult{}, err
	}

	certs, note, err := s.fetch(ctx, d, includeSubdomains)
	if err != nil {
		return LastSeenResult{}, err
	}

	res := LastSeenResult{
		Domain:            d,
		IncludeSubdomains: includeSubdomains,
		FetchedAt:         now(),
		TotalCertificates: len(certs),
		Note:              note,
	}
	if len(certs) == 0 {
		res.Note = join(note, emptyNote(d))
		return res, nil
	}

	first, last := certs[0].NotBefore, certs[0].NotBefore
	for _, c := range certs[1:] {
		if c.NotBefore.Before(first) {
			first = c.NotBefore
		}
		if c.NotBefore.After(last) {
			last = c.NotBefore
		}
	}

	res.Found = true
	res.FirstSeen = &first
	res.LastSeen = &last
	res.LastNotBefore = &last
	return res, nil
}

// fetch reads the domain out of the index and filters the result back to the
// requested scope, so include_subdomains means the same thing here as in the
// names actually on the certificates.
func (s *Service) fetch(ctx context.Context, domain string, includeSubdomains bool) ([]ct.Certificate, string, error) {
	certs, truncated, err := s.client.Issuances(ctx, domain, includeSubdomains)
	if err != nil {
		return nil, "", err
	}

	inScope := certs[:0]
	for _, c := range certs {
		if ct.InScope(c.DNSNames, domain, includeSubdomains) {
			inScope = append(inScope, c)
		}
	}

	var note string
	if truncated {
		note = "certspotter had more pages than were read; the oldest certificates are missing, the most recent are not"
	}
	return inScope, note, nil
}

func notExpired(certs []ct.Certificate, at time.Time) []ct.Certificate {
	out := certs[:0]
	for _, c := range certs {
		if c.NotAfter.IsZero() || c.NotAfter.After(at) {
			out = append(out, c)
		}
	}
	return out
}

// emptyNote says what an empty answer does and does not mean. A domain served
// over plain HTTP, or never served at all, has no certificate to log.
func emptyNote(domain string) string {
	return "no certificate in Certificate Transparency for " + domain +
		"; this dates domains that had a certificate, so absence is not evidence the domain never existed"
}

func join(parts ...string) string {
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, ". ")
}
