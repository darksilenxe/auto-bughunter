# ---------------------------------------------------------------------------
# gau (GetAllUrls) sidecar
#
# Passive URL discovery: fetches known URLs for a host from open sources
# (Wayback Machine, Common Crawl, OTX, URLScan). The backend reaches it via
# the `gau` shim under backend/scripts/shims/, which resolves to
# `docker compose exec -T gau gau ...`.
#
# Built from source and pinned to a known-good release tag. Bump GAU_VERSION
# to upgrade.
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS build
ARG GAU_VERSION=v2.2.4
RUN apk add --no-cache git \
    && go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /go/bin/gau /usr/local/bin/gau
