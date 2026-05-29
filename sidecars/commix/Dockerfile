# ---------------------------------------------------------------------------
# commix sidecar
#
# OS command-injection detection/exploitation tool
# (https://github.com/commixproject/commix, GPL-3.0). This actively injects
# command payloads at the target, so the backend only invokes it when
# ALLOW_DESTRUCTIVE_CHECKS=true. The backend reaches it via the `commix` shim
# under backend/scripts/shims/, which resolves to `docker compose exec -T
# commix commix ...`.
#
# Cloned from source and pinned to a known-good release tag. Bump
# COMMIX_VERSION to upgrade.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine
ARG COMMIX_VERSION=v4.0
RUN apk add --no-cache git \
    && git clone --depth 1 --branch "${COMMIX_VERSION}" \
       https://github.com/commixproject/commix.git /opt/commix \
    && printf '#!/bin/sh\nexec python /opt/commix/commix.py "$@"\n' > /usr/local/bin/commix \
    && chmod +x /usr/local/bin/commix
