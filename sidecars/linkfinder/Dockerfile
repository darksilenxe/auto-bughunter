# ---------------------------------------------------------------------------
# LinkFinder sidecar
#
# Endpoint-discovery tool that extracts links/paths from JavaScript
# (https://github.com/GerbenJavado/LinkFinder, MIT). It fetches the page/JS and
# regex-parses it; it does not inject payloads. The backend reaches it via the
# `linkfinder` shim under backend/scripts/shims/, which resolves to
# `docker compose exec -T linkfinder linkfinder ...`.
#
# Cloned from source and pinned to a known-good commit. Bump LINKFINDER_REF to
# upgrade.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine
ARG LINKFINDER_REF=master
RUN apk add --no-cache git \
    && git clone https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder \
    && cd /opt/linkfinder \
    && git checkout "${LINKFINDER_REF}" \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir . \
    && printf '#!/bin/sh\nexec python /opt/linkfinder/linkfinder.py "$@"\n' > /usr/local/bin/linkfinder \
    && chmod +x /usr/local/bin/linkfinder
