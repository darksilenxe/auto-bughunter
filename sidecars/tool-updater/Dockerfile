# Tool-updater sidecar: a one-shot container that runs on every
# `docker compose up`, refreshes data sources for the security tools
# bundled by the platform (currently the nuclei templates), and queries
# upstream registries for newer releases of every pinned tool. The result
# is a JSON report written to the shared `tool_updates` volume that the
# backend exposes via `GET /api/tools/updates`.
#
# Why a dedicated sidecar instead of running these inside each tool's
# container?
#   * `nuclei -update-templates` needs network access *and* write access
#     to the templates volume, but the per-tool sidecars are intentionally
#     idle (`tail -f /dev/null`) — invoking commands inside them on boot
#     would race the backend's readiness probe.
#   * The version-check loop only needs `curl` + `jq`; bundling that into
#     every tool image would bloat them unnecessarily.

# --- Stage 1: grab the nuclei binary out of the official image ----------
# Keep this tag in lock-step with the `nuclei` service in docker-compose.yml
# so the templates layout we write matches what the runtime nuclei expects.
FROM projectdiscovery/nuclei:v3.8.0 AS nuclei-bin

# --- Stage 2: runtime ---------------------------------------------------
FROM alpine:3.20

# bash for the entrypoint, curl for HTTP, jq for JSON parsing, and ca-certs
# for HTTPS to GitHub. coreutils gives us a sane `date -u +%FT%TZ`.
RUN apk add --no-cache bash ca-certificates coreutils curl jq

# Pull `nuclei` out of the upstream image. The binary is statically linked
# so it runs unchanged on alpine.
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY manifest.json /etc/auto-bughunter/tool-updater/manifest.json
RUN chmod +x /usr/local/bin/entrypoint.sh

# NOTE: tool-updater intentionally runs as root. The shared `nuclei_templates`
# named volume is mounted at /root/nuclei-templates (see docker-compose.yml)
# and is also consumed by `nuclei-service` from the same path; keeping a
# single uid (root, 0) on both ends avoids cross-container ownership issues
# with the named volume. Run is short-lived and one-shot.

# Defaults; overridable via compose.
ENV NUCLEI_TEMPLATES_DIR=/root/nuclei-templates \
    TOOL_UPDATES_DIR=/var/lib/auto-bughunter/updates \
    TOOL_UPDATER_MANIFEST=/etc/auto-bughunter/tool-updater/manifest.json

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
