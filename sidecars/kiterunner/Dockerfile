# ---------------------------------------------------------------------------
# Kiterunner sidecar
#
# Bundles Assetnote's `kr` (kiterunner) CLI plus every wordlist published at
# https://wordlists.assetnote.io. The wordlists live on a named docker volume
# (`assetnote_wordlists` -> /wordlists) that is also read-only mounted into
# the backend container at the same path, so the Go scanner can pass
# `/wordlists/<category>/<file>` straight through to ffuf, gobuster, kr, etc.
#
# Wordlists are fetched on first container start (not at image build time) so
# that:
#   * the image stays small,
#   * the listing is always current with the upstream manifest,
#   * the data is cached on the named volume across container restarts.
#
# The matching shim under backend/scripts/shims/kr resolves to
# `docker compose exec -T kiterunner kr ...`, which means the Go scanner's
# existing exec.LookPath / exec.CommandContext code keeps working unchanged.
# ---------------------------------------------------------------------------

# --- Stage 1: pull the kiterunner release binary -------------------------
FROM alpine:3.20 AS kr-fetch

# Bump KITERUNNER_VERSION when a new release is published at
# https://github.com/assetnote/kiterunner/releases. Releases are infrequent
# (the project is in maintenance mode) so a hard pin is preferred over
# `latest` to keep the image deterministic.
ARG KITERUNNER_VERSION=1.0.2
ARG TARGETARCH=amd64

RUN apk add --no-cache curl tar ca-certificates

# Assetnote only publishes amd64 release artifacts. Anything else fails fast
# with a clear message rather than silently shipping a broken binary.
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) ARCH=amd64 ;; \
      *) echo "kiterunner has no upstream release for arch=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/assetnote/kiterunner/releases/download/v${KITERUNNER_VERSION}/kiterunner_${KITERUNNER_VERSION}_linux_${ARCH}.tar.gz"; \
    curl -fSL -o /tmp/kr.tgz "$url"; \
    mkdir -p /out; \
    tar -xzf /tmp/kr.tgz -C /out kr; \
    chmod +x /out/kr

# --- Stage 2: runtime image ---------------------------------------------
FROM alpine:3.20

# curl + jq are used by the entrypoint to parse the Assetnote manifest and
# stream every listed wordlist into /wordlists. ca-certificates is required
# for HTTPS downloads. coreutils gives us a portable `mkdir -p` etc.
RUN apk add --no-cache ca-certificates curl jq coreutils

COPY --from=kr-fetch /out/kr /usr/local/bin/kr

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

# Wordlist cache lives on a docker named volume so it survives restarts and
# is shared (read-only) with the backend.
VOLUME ["/wordlists"]
ENV WORDLIST_DIR=/wordlists

# `entrypoint.sh` downloads any missing Assetnote wordlists, then keeps the
# container alive so `docker compose exec -T kiterunner kr ...` works. Each
# invocation is a short-lived child of this PID 1.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
