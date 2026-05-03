# ---------------------------------------------------------------------------
# Build stage — compile the Go server binary.
# ---------------------------------------------------------------------------
FROM golang:1.25-alpine AS build
WORKDIR /app

COPY go.mod .
RUN go mod download

COPY . .
RUN go build -o /out/server ./cmd/server

# ---------------------------------------------------------------------------
# Runtime image
#
# The backend used to bundle every security tool it shells out to (nuclei,
# OWASP ZAP + Java + Python, headless Chromium, ...). That ballooned the image
# to ~1 GB and made every backend rebuild also rebuild the tools.
#
# Instead, each heavy dependency now lives in its own Docker Compose sidecar
# (see ../docker-compose.yml: `nuclei`, `zap`, `chromium`).
#
# Docker CLI dependencies are OPTIONAL:
#   * When USE_HTTP_TOOL_SERVICES=true, the backend uses HTTP to communicate
#     with tool sidecars (nuclei-service, etc), eliminating the Docker socket
#     requirement entirely.
#   * When USE_HTTP_TOOL_SERVICES=false (default), the backend falls back to
#     `docker compose exec` via shim scripts, which requires docker-cli and
#     the Docker socket mount.
# ---------------------------------------------------------------------------
FROM alpine:latest

# Install base dependencies
RUN apk add --no-cache \
    ca-certificates

# Optional: Install docker-cli for legacy exec mode (only needed when USE_HTTP_TOOL_SERVICES=false)
# Uncomment these lines if you need docker compose exec support:
# RUN apk add --no-cache \
#     docker-cli \
#     docker-cli-compose

WORKDIR /app

COPY --from=build /out/server /app/server

# Sidecar shims — these live on $PATH so the existing `exec.LookPath(...)`
# code in the Go scanner keeps finding `nuclei`, `zap-baseline.py`, etc.
# without any backend code changes. They forward stdin/stdout/stderr/exit
# code unchanged.
COPY scripts/shims/sidecar-exec      /usr/local/bin/sidecar-exec
COPY scripts/shims/nuclei            /usr/local/bin/nuclei
COPY scripts/shims/zap-baseline.py   /usr/local/bin/zap-baseline.py
# ProjectDiscovery suite — all served by the shared `projectdiscovery`
# sidecar (see ../sidecars/projectdiscovery/Dockerfile).
COPY scripts/shims/subfinder         /usr/local/bin/subfinder
COPY scripts/shims/httpx             /usr/local/bin/httpx
COPY scripts/shims/cloudlist         /usr/local/bin/cloudlist
COPY scripts/shims/naabu             /usr/local/bin/naabu
COPY scripts/shims/dnsx              /usr/local/bin/dnsx
COPY scripts/shims/shuffledns        /usr/local/bin/shuffledns
COPY scripts/shims/katana            /usr/local/bin/katana
COPY scripts/shims/tlsx              /usr/local/bin/tlsx
COPY scripts/shims/cdncheck          /usr/local/bin/cdncheck
COPY scripts/shims/asnmap            /usr/local/bin/asnmap
COPY scripts/shims/vulnx             /usr/local/bin/vulnx
# Fuzzing / dirbusting — each in its own sidecar; both rely on the shared
# tmp volume mounted at $SHARED_TMP_DIR so that the wordlist file the
# backend writes is visible inside the sidecar at the same path.
COPY scripts/shims/ffuf              /usr/local/bin/ffuf
COPY scripts/shims/gobuster          /usr/local/bin/gobuster
# Kiterunner — `kr` runs in the kiterunner sidecar, which also hosts the
# Assetnote wordlist cache mounted at /wordlists in this container.
COPY scripts/shims/kr                /usr/local/bin/kr
# CMS / web app scanners — keep Python (sqlmap), Perl (nikto) and Ruby
# (wpscan) runtimes out of this image entirely.
COPY scripts/shims/sqlmap            /usr/local/bin/sqlmap
COPY scripts/shims/nikto             /usr/local/bin/nikto
COPY scripts/shims/wpscan            /usr/local/bin/wpscan
# LLM-assisted XSS scanner — runs in the `xssmap` sidecar (Python +
# Playwright + an Ollama client that reuses the local `ollama` service).
COPY scripts/shims/xssmap            /usr/local/bin/xssmap
RUN chmod +x /usr/local/bin/sidecar-exec \
             /usr/local/bin/nuclei \
             /usr/local/bin/zap-baseline.py \
             /usr/local/bin/subfinder \
             /usr/local/bin/httpx \
             /usr/local/bin/cloudlist \
             /usr/local/bin/naabu \
             /usr/local/bin/dnsx \
             /usr/local/bin/shuffledns \
             /usr/local/bin/katana \
             /usr/local/bin/tlsx \
             /usr/local/bin/cdncheck \
             /usr/local/bin/asnmap \
             /usr/local/bin/vulnx \
             /usr/local/bin/ffuf \
             /usr/local/bin/gobuster \
             /usr/local/bin/kr \
             /usr/local/bin/sqlmap \
             /usr/local/bin/nikto \
             /usr/local/bin/wpscan \
             /usr/local/bin/xssmap

# Default chromedp wiring — the `chromium` sidecar exposes the DevTools
# protocol on port 9222. The Go scanner picks this up via CHROME_REMOTE_URL
# (see backend/internal/scanner/browser.go).
ENV CHROME_REMOTE_URL=http://chromium:9222 \
    PORT=8080
EXPOSE 8080

CMD ["/app/server"]
