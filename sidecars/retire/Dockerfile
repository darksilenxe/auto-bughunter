# ---------------------------------------------------------------------------
# retire.js sidecar
#
# Scanner for JavaScript libraries with known vulnerabilities
# (https://github.com/RetireJS/retire.js, Apache-2.0). It reads JavaScript
# bundles the backend downloads into the shared_tmp volume and reports
# vulnerable components. The backend reaches it via the `retire` shim under
# backend/scripts/shims/, which resolves to
# `docker compose exec -T retire retire ...`.
#
# Pinned to a known-good npm release. Bump RETIRE_VERSION to upgrade.
# ---------------------------------------------------------------------------
FROM node:20-alpine
ARG RETIRE_VERSION=5.2.4
RUN npm install -g "retire@${RETIRE_VERSION}"
