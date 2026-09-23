// Package mcptools exposes the service over MCP.
//
// The descriptions carry the one thing a model gets wrong otherwise: what an
// empty answer means. Certificate Transparency records certificates, not
// domains, so a name served over plain HTTP — or never served at all — is
// invisible here. These tools date the domains that had a certificate.
package mcptools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sebdraven/mcp-ct/internal/service"
)

type registry struct{ svc *service.Service }

func Register(s *mcp.Server, svc *service.Service) {
	r := &registry{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "ct_domain_certs",
		Description: "List every certificate seen in Certificate Transparency for a domain, newest first. " +
			"Each one carries its validity window (not_before, not_after), its issuer, all the DNS names it covers, and its certspotter issuance id. " +
			"Set include_subdomains to widen the query from the exact name to everything under it; set include_expired to false to keep only certificates still valid today. " +
			"An empty result means no certificate was ever logged for the name, which is not the same as the domain never existing: a host served over plain HTTP has no certificate to log.",
	}, r.certs)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ct_domain_last_seen",
		Description: "Date a domain from its certificates: when the most recent one was issued (last_not_before), how many were ever issued, and the window they span (first_seen, last_seen). " +
			"This is the quickest read on whether a name is still in use — a domain whose newest certificate was issued years ago has not been re-provisioned since. " +
			"Expired certificates are counted on purpose; they are the historical evidence. " +
			"It answers about issuance, not about traffic: a certificate is renewed by whoever controls the name, which may not be whoever originally ran the site. " +
			"found=false means nothing was logged, not that the domain is unregistered.",
	}, r.lastSeen)

	mcp.AddTool(s, &mcp.Tool{
		Name: "ct_domain_subdomains",
		Description: "Every certificate logged for a domain and everything under it, newest first — the same output as ct_domain_certs with include_subdomains set. " +
			"Reading the dns_names across the results enumerates the subdomains that were ever given a certificate, which is the usual reason to ask. " +
			"It finds only what was certificated: internal names served over plain HTTP, or never served, leave no trace in Certificate Transparency.",
	}, r.subdomains)
}

type certsInput struct {
	Domain            string `json:"domain" jsonschema:"domain to look up, e.g. 'example.com' — a registrable name, not a URL"`
	IncludeSubdomains bool   `json:"include_subdomains,omitempty" jsonschema:"also match anything under the domain (default false)"`
	IncludeExpired    *bool  `json:"include_expired,omitempty" jsonschema:"keep certificates that have already expired (default true)"`
}

type lastSeenInput struct {
	Domain            string `json:"domain" jsonschema:"domain to date, e.g. 'example.com'"`
	IncludeSubdomains bool   `json:"include_subdomains,omitempty" jsonschema:"also count certificates issued under the domain (default false)"`
}

type subdomainsInput struct {
	Domain         string `json:"domain" jsonschema:"domain whose subdomains to enumerate, e.g. 'example.com'"`
	IncludeExpired *bool  `json:"include_expired,omitempty" jsonschema:"keep certificates that have already expired (default true)"`
}

// includeExpired defaults to true: the expired certificates are most of the
// history, and dropping them by accident would make a dead domain look absent
// rather than dead.
func includeExpired(v *bool) bool { return v == nil || *v }

func (r *registry) certs(ctx context.Context, _ *mcp.CallToolRequest, in certsInput) (*mcp.CallToolResult, service.CertsResult, error) {
	res, err := r.svc.Certs(ctx, in.Domain, in.IncludeSubdomains, includeExpired(in.IncludeExpired))
	return nil, res, err
}

func (r *registry) lastSeen(ctx context.Context, _ *mcp.CallToolRequest, in lastSeenInput) (*mcp.CallToolResult, service.LastSeenResult, error) {
	res, err := r.svc.LastSeen(ctx, in.Domain, in.IncludeSubdomains)
	return nil, res, err
}

func (r *registry) subdomains(ctx context.Context, _ *mcp.CallToolRequest, in subdomainsInput) (*mcp.CallToolResult, service.CertsResult, error) {
	res, err := r.svc.Certs(ctx, in.Domain, true, includeExpired(in.IncludeExpired))
	return nil, res, err
}
