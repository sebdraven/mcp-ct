// Package certspotter is a client over the SSLMate Cert Spotter API
// (https://sslmate.com/help/reference/ct_search_api_v1).
//
// The raw Certificate Transparency logs cannot be queried by domain: an RFC
// 6962 log answers "give me entry N", not "give me every certificate for
// example.com". certspotter has already built that index, which is what this
// package talks to.
//
// Issuances come back oldest-first in pages keyed by the id of the last one
// seen, so the newest certificate — the one every question here ends up asking
// about — is on the final page. Pagination therefore runs to exhaustion rather
// than stopping early.
package certspotter

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sebdraven/mcp-ct/internal/ct"
)

const DefaultBaseURL = "https://api.certspotter.com"

const (
	// pageLimit is the API maximum. The free plan meters whole requests, not
	// results, so the largest page is also the cheapest way to read a domain.
	pageLimit = 1000

	// maxPages bounds a runaway domain. A million-certificate CDN apex would
	// otherwise page until the context died; the caller is told when this bites.
	maxPages = 50

	maxAttempts        = 4
	defaultBackoff     = 2 * time.Second
	maxBackoff         = 30 * time.Second
	defaultHTTPTimeout = 60 * time.Second
)

// ErrUnavailable marks the failures that are certspotter's rather than the
// caller's — quota exhaustion, a rejected token, a server-side fault, the
// network — so a caller can tell "no answer" from "no certificates".
var ErrUnavailable = errors.New("certspotter unavailable")

type Client struct {
	token     string
	baseURL   string
	userAgent string
	backoff   time.Duration
	http      *http.Client
}

type Option func(*Client)

func WithBaseURL(u string) Option {
	return func(c *Client) {
		if u = strings.TrimRight(strings.TrimSpace(u), "/"); u != "" {
			c.baseURL = u
		}
	}
}

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) { c.http = h }
}

func WithUserAgent(ua string) Option {
	return func(c *Client) {
		if ua = strings.TrimSpace(ua); ua != "" {
			c.userAgent = ua
		}
	}
}

// WithBackoff sets the first retry delay; later ones double it. Tests use it to
// avoid sleeping through a real backoff schedule.
func WithBackoff(d time.Duration) Option {
	return func(c *Client) { c.backoff = d }
}

func New(token string, opts ...Option) *Client {
	c := &Client{
		token:     strings.TrimSpace(token),
		baseURL:   DefaultBaseURL,
		userAgent: ct.UserAgent("dev"),
		backoff:   defaultBackoff,
		http:      &http.Client{Timeout: defaultHTTPTimeout},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// HasToken reports whether a token was supplied. Without one the API still
// answers, at a much lower rate.
func (c *Client) HasToken() bool { return c.token != "" }

// APIError carries the status of a rejected request.
type APIError struct {
	StatusCode int
	Body       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("certspotter: rejected (%d) — check CERTSPOTTER_TOKEN", e.StatusCode)
	case http.StatusTooManyRequests:
		return "certspotter: rate limited (429) — the free plan caps queries per hour, see https://sslmate.com/help/reference/ct_search_api_v1"
	}
	body := strings.TrimSpace(e.Body)
	if len(body) > 200 {
		body = body[:200]
	}
	return fmt.Sprintf("certspotter: HTTP %d: %s", e.StatusCode, body)
}

// Is makes errors.Is(err, ErrUnavailable) true for the statuses that mean the
// service, not the request, is at fault.
func (e *APIError) Is(target error) bool {
	if target != ErrUnavailable {
		return false
	}
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	}
	return e.StatusCode >= 500
}

// issuance is one record as the API returns it. dns_names, issuer and cert are
// only populated when asked for with expand.
type issuance struct {
	ID        string    `json:"id"`
	DNSNames  []string  `json:"dns_names"`
	NotBefore string    `json:"not_before"`
	NotAfter  string    `json:"not_after"`
	Issuer    issuerRef `json:"issuer"`
	Cert      certRef   `json:"cert"`
}

type issuerRef struct {
	Name string `json:"name"`
}

type certRef struct {
	Data string `json:"data"` // base64 DER
}

// Issuances returns every certificate certspotter holds for a domain,
// deduplicated on issuance id: one certificate submitted to several logs is
// reported once per log, and the id is what tells those apart.
//
// truncated reports that maxPages was reached and older issuances remain
// unread. The newest are always read: pages run oldest-first, so truncation
// loses the tail, not the head.
func (c *Client) Issuances(ctx context.Context, domain string, includeSubdomains bool) (certs []ct.Certificate, truncated bool, err error) {
	seen := make(map[string]bool)
	after := ""

	for page := 0; page < maxPages; page++ {
		q := url.Values{}
		q.Set("domain", domain)
		q.Set("include_subdomains", strconv.FormatBool(includeSubdomains))
		q.Set("limit", strconv.Itoa(pageLimit))
		q["expand"] = []string{"dns_names", "issuer", "cert"}
		if after != "" {
			q.Set("after", after)
		}

		batch, err := c.page(ctx, q)
		if err != nil {
			return nil, false, err
		}
		if len(batch) == 0 {
			return certs, false, nil
		}

		for _, is := range batch {
			after = is.ID
			if seen[is.ID] {
				continue
			}
			seen[is.ID] = true
			cert, err := is.certificate()
			if err != nil {
				return nil, false, err
			}
			certs = append(certs, cert)
		}

		// A short page is the last page.
		if len(batch) < pageLimit {
			return certs, false, nil
		}
	}
	return certs, true, nil
}

// page fetches one slice of the result set, retrying the failures that pass.
func (c *Client) page(ctx context.Context, q url.Values) ([]issuance, error) {
	var last error
	wait := c.backoff

	for attempt := range maxAttempts {
		if attempt > 0 {
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			if wait *= 2; wait > maxBackoff {
				wait = maxBackoff
			}
		}

		body, err := c.get(ctx, q)
		if err == nil {
			var out []issuance
			if err := json.Unmarshal(body, &out); err != nil {
				return nil, fmt.Errorf("certspotter: decoding issuances: %w", err)
			}
			return out, nil
		}

		last = err
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if !errors.Is(apiErr, ErrUnavailable) {
				return nil, err
			}
			// 401/403 will not improve with a second try.
			if apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden {
				return nil, err
			}
			if apiErr.RetryAfter > 0 {
				wait = min(apiErr.RetryAfter, maxBackoff)
			}
		}
	}
	return nil, last
}

func (c *Client) get(ctx context.Context, q url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/issuances?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("certspotter: %w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(body),
			RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		}
	}
	return io.ReadAll(resp.Body)
}

func (is issuance) certificate() (ct.Certificate, error) {
	notBefore, err := parseTime(is.NotBefore)
	if err != nil {
		return ct.Certificate{}, fmt.Errorf("certspotter: issuance %s: not_before: %w", is.ID, err)
	}
	notAfter, err := parseTime(is.NotAfter)
	if err != nil {
		return ct.Certificate{}, fmt.Errorf("certspotter: issuance %s: not_after: %w", is.ID, err)
	}

	cert := ct.Certificate{
		ID:        is.ID,
		Issuer:    strings.TrimSpace(is.Issuer.Name),
		DNSNames:  ct.NormalizeNames(is.DNSNames),
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	// The validity window is what dates a domain, so it is not left to the
	// field alone: expand=cert is requested anyway, and the DER inside carries
	// the same dates and the issuer's own name for the record.
	if cert.NotBefore.IsZero() || cert.NotAfter.IsZero() || cert.Issuer == "" {
		if parsed, err := parseDER(is.Cert.Data); err == nil {
			if cert.NotBefore.IsZero() {
				cert.NotBefore = parsed.NotBefore.UTC()
			}
			if cert.NotAfter.IsZero() {
				cert.NotAfter = parsed.NotAfter.UTC()
			}
			if cert.Issuer == "" {
				cert.Issuer = parsed.Issuer.String()
			}
			if len(cert.DNSNames) == 0 {
				cert.DNSNames = ct.NormalizeNames(parsed.DNSNames)
			}
		}
	}
	return cert, nil
}

func parseDER(b64 string) (*x509.Certificate, error) {
	if strings.TrimSpace(b64) == "" {
		return nil, fmt.Errorf("no certificate data")
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func parseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// retryAfter reads the header in either of its forms, seconds or HTTP-date.
func retryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
