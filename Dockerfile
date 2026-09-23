# Build stage.
FROM golang:1.27 AS build

WORKDIR /src

# Stamped into the binary so a running container reports the version it was
# built from. Defaults to "container" rather than a number: an image built
# outside the release workflow should not claim a release.
ARG VERSION=container

# Dependencies first, so a source-only change does not refetch the module graph.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO off and a stripped binary: the runtime stage has no libc to link against.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/mcp-ct ./cmd/mcp-ct

# Runtime stage.
#
# The image exists for the streamable-HTTP transport — a server someone can
# reach — rather than for the stdio process a desktop client spawns. It carries
# no data and no credentials: CERTSPOTTER_TOKEN is read from the environment at
# run time, and without it queries go out unauthenticated at a much lower rate.
#
# distroless static ships a CA bundle, which is load-bearing here: every lookup
# is an HTTPS call, and on scratch they would all fail on certificate errors.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/mcp-ct /usr/local/bin/mcp-ct

EXPOSE 8080
# Container runs the HTTP transport by default; override args for stdio.
ENV MCP_TRANSPORT=http

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mcp-ct"]
