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

# Install base dependencies.
#   * ca-certificates — outbound HTTPS to sidecars/AI providers/targets.
#   * python3 — the ToolBuilder/AIToolCalling agents shell out to `python3`
#     to execute the custom probe scripts they generate at runtime
#     (see backend/internal/toolbuilder/toolbuilder.go). Without it those
#     agents fail with "executable file not found".
RUN apk add --no-cache \
    ca-certificates \
    python3

# Optional: Install docker-cli for legacy exec mode (only needed when USE_HTTP_TOOL_SERVICES=false)
# Uncomment these lines if you need docker compose exec support:
# RUN apk add --no-cache \
#     docker-cli \
#     docker-cli-compose

WORKDIR /app

COPY --from=build /out/server /app/server

# Bundle the accuracy-bench corpus so the in-app Accuracy page can grade
# scans against the same manifests the nightly CI workflow uses.
COPY cmd/accuracy-bench/testdata/corpus /app/accuracy-corpus

# Sidecar shims — these live on $PATH so the existing `exec.LookPath(...)`
# code in the Go scanner keeps finding `nuclei`, `zap-baseline.py`, etc.
# without any backend code changes. They forward stdin/stdout/stderr/exit
# code unchanged.
COPY scripts/shims/ /usr/local/bin/
RUN find /usr/local/bin -type f -exec sed -i 's/\r$//' {} + && \
    chmod +x /usr/local/bin/*

# Default chromedp wiring — the `chromium` sidecar exposes the DevTools
# protocol on port 9222. The Go scanner picks this up via CHROME_REMOTE_URL
# (see backend/internal/scanner/browser.go).
ENV CHROME_REMOTE_URL=http://chromium:9222 \
    PORT=8080 \
    ACCURACY_CORPUS_DIR=/app/accuracy-corpus
EXPOSE 8080

CMD ["/app/server"]
