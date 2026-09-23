# mcp-ct

An MCP server for retrospective Certificate Transparency lookups: given a
domain, every certificate ever logged for it, and when the last one was issued.

It queries an index, not the logs. An RFC 6962 log answers "give me entry N",
never "give me every certificate for example.com" — searching one by domain
would mean downloading and indexing it yourself. [SSLMate's Cert
Spotter](https://sslmate.com/help/reference/ct_search_api_v1) has already built
that index, so it is what this asks.

The question it exists for is dating a domain: a name whose newest certificate
was issued four years ago has not been re-provisioned since.

## Tools

| Tool | What it answers |
|---|---|
| `ct_domain_certs` | every certificate logged for a domain — validity window, issuer, SANs, issuance id |
| `ct_domain_last_seen` | when the most recent certificate was issued, how many there have been, and the window they span |
| `ct_domain_subdomains` | the same list widened to everything under the domain, which enumerates the subdomains that were ever certificated |

Results are sorted by `not_before`, newest first. Timestamps are RFC 3339 in
UTC. `include_expired` defaults to true: expired certificates are most of the
history, and a dead domain is dated by the certificate that expired, not by the
absence of a live one.

## Configuration

| Variable | Meaning |
|---|---|
| `CERTSPOTTER_TOKEN` | the Cert Spotter API key; on macOS it can live in the keychain under the service name `api.certspotter.com` instead |
| `MCP_TRANSPORT` | `stdio` (default) or `http` |
| `MCP_HTTP_ADDR` | listen address for the HTTP transport (default `:8080`) |

The key is issued from the API Credentials page of an SSLMate account. It is
read from the environment only — never passed as an argument, where it would
land in the process list and the shell history.

Without a key the API still answers, at a much lower rate limit; a busy domain
will run into 429s.

```json
{
  "mcpServers": {
    "ct": {
      "command": "/path/to/mcp-ct",
      "env": { "CERTSPOTTER_TOKEN": "..." }
    }
  }
}
```

Storing the key in the keychain keeps it out of the config file:

```sh
security add-generic-password -s api.certspotter.com -a "$USER" -w
```

The `-w` with no value prompts, so the key never reaches your shell history.

## One-shot lookups

The binary answers from the command line without a client, which is what you
want when checking a domain or scripting a sweep.

```sh
mcp-ct -domain example.com
mcp-ct -domain example.com -subdomains
mcp-ct -domain example.com -certs
```

## Container

The image exists for the streamable-HTTP transport — a server someone can reach
— rather than the stdio process a desktop client spawns.

```sh
docker run --rm -p 8080:8080 -e CERTSPOTTER_TOKEN ghcr.io/sebdraven/mcp-ct:edge
```

## Caveats

- **Absence proves nothing.** Certificate Transparency records certificates, not
  domains. A host served over plain HTTP, or never served at all, leaves no
  trace. These tools date the domains that had a certificate.
- **Issuance is not traffic.** A certificate is renewed by whoever controls the
  name, which may no longer be whoever ran the site.
- **Quotas are per plan**, and reading a domain costs one request per page of a
  thousand issuances. 429s and 5xx are retried with backoff, honouring
  `Retry-After`; a domain with more than fifty pages is reported as truncated —
  the pages run oldest-first, so what is lost is the tail, not the recent
  certificates.
- **Subdomain enumeration is partial by construction.** It finds the names that
  were given a certificate, and wildcard certificates hide the names they cover.
