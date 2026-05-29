# ---------------------------------------------------------------------------
# Arjun sidecar
#
# HTTP parameter-discovery tool (https://github.com/s0md3v/Arjun). Sends many
# requests with candidate parameter names to reveal hidden parameters but does
# not send exploit payloads. The backend reaches it via the `arjun` shim under
# backend/scripts/shims/, which resolves to `docker compose exec -T arjun
# arjun ...`.
#
# Arjun writes its JSON results (-oJ <path>) into the shared_tmp volume, which
# this sidecar mounts read-write at the same path the backend uses.
#
# Pinned to a known-good PyPI release. Bump ARJUN_VERSION to upgrade.
# ---------------------------------------------------------------------------
FROM python:3.12-alpine
ARG ARJUN_VERSION=2.2.7
RUN pip install --no-cache-dir "arjun==${ARJUN_VERSION}"
