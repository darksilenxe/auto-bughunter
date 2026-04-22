# ---------------------------------------------------------------------------
# XSSMap sidecar
#
# Bundles the third-party XSSMap (https://github.com/secdec/xssmap) tool
# in a self-contained Python + Playwright image. The backend never imports
# XSSMap source — it shells out to the `xssmap` CLI installed here via the
# matching shim under backend/scripts/shims/xssmap.
#
# License note: XSSMap is GPL-3.0. We **do not** vendor or modify its source
# in this repository — it is installed unmodified at image-build time and
# invoked as an external process. That keeps the rest of the auto-bughunter
# codebase clear of GPL contamination.
#
# Ollama reuse: the sidecar reaches the existing `ollama` Docker Compose
# service via XSSMAP_OLLAMA_URL (default http://ollama:11434). The model
# defaults to whatever OLLAMA_MODEL is set to in the platform .env, falling
# back to phi3:mini which is pre-pulled by the `ollama-init` service.
# ---------------------------------------------------------------------------

FROM mcr.microsoft.com/playwright/python:v1.47.0-jammy

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    XSSMAP_HOME=/opt/xssmap

WORKDIR /opt/xssmap

# Pinned commit/branch to keep the image build reproducible. Bump as needed.
# Source: secdec/xssmap (the original canonical XSSMap repository).
ARG XSSMAP_REF=master

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 # Avoid any interactive credential prompting in non-interactive CI builds.
 # If the upstream repo becomes private/removed/redirects, fail loudly instead
 # of hanging or erroring with an unhelpful prompt-related message.
 && export GIT_TERMINAL_PROMPT=0 \
 && git -c credential.helper= -c core.askpass=true \
      clone --depth 1 --branch "${XSSMAP_REF}" \
      https://github.com/secdec/xssmap.git /opt/xssmap/src \
 && if [ -f /opt/xssmap/src/requirements.txt ]; then \
        pip install --no-cache-dir -r /opt/xssmap/src/requirements.txt ; \
    fi \
 && pip install --no-cache-dir requests beautifulsoup4 lxml

# Wrapper exposing a stable CLI surface (`xssmap scan --url <t> --output json
# [--max-payloads N] [--model M] [--ollama-url URL]`) regardless of upstream
# CLI churn. Translates those flags into the actual entrypoint that the
# upstream project ships.
COPY xssmap-wrapper.py /usr/local/bin/xssmap
RUN chmod +x /usr/local/bin/xssmap

# Keep the container alive so the backend can `docker compose exec -T xssmap
# xssmap ...` on demand (same pattern as nuclei/zap/sqlmap sidecars).
ENTRYPOINT ["sh", "-c", "tail -f /dev/null"]
