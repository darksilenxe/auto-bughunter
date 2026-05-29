# ---------------------------------------------------------------------------
# TruffleHog sidecar
#
# Secret-scanning tool (https://github.com/trufflesecurity/trufflehog,
# AGPL-3.0). It scans the JavaScript bundles the backend downloads into the
# shared_tmp volume for committed credentials. The backend reaches it via the
# `trufflehog` shim under backend/scripts/shims/, which resolves to
# `docker compose exec -T trufflehog trufflehog ...`.
#
# Uses the official image pinned to a known-good release tag. Bump
# TRUFFLEHOG_VERSION to upgrade.
# ---------------------------------------------------------------------------
ARG TRUFFLEHOG_VERSION=3.82.6
FROM trufflesecurity/trufflehog:${TRUFFLEHOG_VERSION}
