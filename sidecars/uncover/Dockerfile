# ---------------------------------------------------------------------------
# Uncover sidecar
#
# Exposed-host discovery tool (https://github.com/projectdiscovery/uncover,
# MIT). It queries third-party search engines (Shodan, Censys, Fofa, …) for
# hosts/services related to the target rather than touching the target itself.
# API keys are supplied via environment variables (e.g. SHODAN_API_KEY). The
# backend reaches it via the `uncover` shim under backend/scripts/shims/, which
# resolves to `docker compose exec -T uncover uncover ...`.
#
# Built from source and pinned to a known-good release tag. Bump
# UNCOVER_VERSION to upgrade.
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS build
ARG UNCOVER_VERSION=v1.1.0
RUN apk add --no-cache git \
    && go install github.com/projectdiscovery/uncover/cmd/uncover@${UNCOVER_VERSION}

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/uncover /usr/local/bin/uncover
