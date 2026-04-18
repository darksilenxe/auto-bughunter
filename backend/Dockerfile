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
# (see ../docker-compose.yml: `nuclei`, `zap`, `chromium`). The backend only
# needs:
#   * The compiled Go binary
#   * `ca-certificates` for outbound HTTPS
#   * The Docker CLI + Compose plugin so the shim scripts under
#     `/usr/local/bin` can `docker compose exec -T <svc> <tool> ...`
# ---------------------------------------------------------------------------
FROM alpine:latest

RUN apk add --no-cache \
    ca-certificates \
    docker-cli \
    docker-cli-compose

WORKDIR /app

COPY --from=build /out/server /app/server

# Sidecar shims — these live on $PATH so the existing `exec.LookPath(...)`
# code in the Go scanner keeps finding `nuclei`, `zap-baseline.py`, etc.
# without any backend code changes. They forward stdin/stdout/stderr/exit
# code unchanged.
COPY scripts/shims/sidecar-exec      /usr/local/bin/sidecar-exec
COPY scripts/shims/nuclei            /usr/local/bin/nuclei
COPY scripts/shims/zap-baseline.py   /usr/local/bin/zap-baseline.py
RUN chmod +x /usr/local/bin/sidecar-exec \
             /usr/local/bin/nuclei \
             /usr/local/bin/zap-baseline.py

# Default chromedp wiring — the `chromium` sidecar exposes the DevTools
# protocol on port 9222. The Go scanner picks this up via CHROME_REMOTE_URL
# (see backend/internal/scanner/browser.go).
ENV CHROME_REMOTE_URL=http://chromium:9222 \
    PORT=8080
EXPOSE 8080

CMD ["/app/server"]
