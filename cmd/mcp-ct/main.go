// Command mcp-ct serves retrospective Certificate Transparency lookups over
// MCP: given a domain, every certificate ever logged for it and when the last
// one was issued.
//
// It queries the index, not the logs. An RFC 6962 log answers "give me entry
// N", never "give me every certificate for example.com"; certspotter has
// already built that index, so it is what is asked.
//
// It speaks either stdio (default, for local clients like Claude Desktop) or
// streamable HTTP (for remote or containerised deployment).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sebdraven/mcp-ct/internal/certspotter"
	"github.com/sebdraven/mcp-ct/internal/ct"
	"github.com/sebdraven/mcp-ct/internal/mcptools"
	"github.com/sebdraven/mcp-ct/internal/service"
)

// version is injected at build time with -ldflags "-X main.version=...".
// The default is deliberately "dev" rather than a number: a locally built
// binary that announces a release version lies to whoever reads it, and the
// MCP client shows this string as the server's identity.
var version = "dev"

func main() {
	var (
		transport  = flag.String("transport", envOr("MCP_TRANSPORT", "stdio"), "transport: stdio or http")
		addr       = flag.String("addr", envOr("MCP_HTTP_ADDR", ":8080"), "HTTP listen address (http transport only)")
		lookup     = flag.String("domain", "", "date one domain and exit")
		certs      = flag.Bool("certs", false, "with -domain, list the certificates rather than the summary")
		subdomains = flag.Bool("subdomains", false, "with -domain, include everything under the domain")
		showVer    = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	// stderr, always: on stdio anything on stdout corrupts the protocol stream.
	log.SetOutput(os.Stderr)

	ua := ct.UserAgent(version)
	token := certspotter.Token()
	if token == "" {
		log.Print("CERTSPOTTER_TOKEN unset: queries go out unauthenticated, at a much lower rate limit")
	}

	svc := service.New(certspotter.New(token,
		certspotter.WithBaseURL(os.Getenv("CERTSPOTTER_BASE_URL")),
		certspotter.WithUserAgent(ua)))
	ctx := context.Background()

	if *lookup != "" {
		if *certs {
			exitWith(svc.Certs(ctx, *lookup, *subdomains, true))
		}
		exitWith(svc.LastSeen(ctx, *lookup, *subdomains))
	}

	server := mcp.NewServer(&mcp.Implementation{
		Name:    "mcp-ct",
		Version: version,
	}, nil)
	mcptools.Register(server, svc)

	switch *transport {
	case "stdio":
		log.Printf("mcp-ct %s on stdio", version)
		if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil {
			log.Fatalf("server: %v", err)
		}
	case "http":
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
			return server
		}, nil)
		log.Printf("mcp-ct %s listening on %s (streamable HTTP)", version, *addr)
		if err := http.ListenAndServe(*addr, handler); err != nil {
			log.Fatalf("server: %v", err)
		}
	default:
		log.Fatalf("unknown transport %q (want stdio or http)", *transport)
	}
}

func exitWith(v any, err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatalf("encoding result: %v", err)
	}
	os.Exit(0)
}
