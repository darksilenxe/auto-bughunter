#!/usr/bin/env bash
#
# Tool-updater entrypoint. Runs once per `docker compose up`:
#
#   1. Refreshes the nuclei templates in $NUCLEI_TEMPLATES_DIR (shared
#      with the `nuclei` sidecar via the `nuclei_templates` named volume).
#   2. Queries the GitHub Releases API for every tool listed in
#      $TOOL_UPDATER_MANIFEST and compares the latest tag to the `current`
#      pin. Anything ahead of the pin is reported as `outdated`.
#   3. Writes a structured JSON report to $TOOL_UPDATES_DIR/report.json
#      and a human-readable summary to stdout.
#
# Knobs (all optional):
#   GITHUB_TOKEN              — bearer token to lift GitHub's 60 req/h
#                               unauthenticated rate limit to 5000 req/h.
#   TOOL_UPDATER_SKIP_NUCLEI  — set to 1 to skip the nuclei template sync
#                               (useful for offline / air-gapped boots).
#   TOOL_UPDATER_SKIP_VERSION — set to 1 to skip the version checks.
#   TOOL_UPDATER_HTTP_TIMEOUT — per-request curl timeout in seconds (default 15).

set -euo pipefail

NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-/home/appuser/nuclei-templates}"
TOOL_UPDATES_DIR="${TOOL_UPDATES_DIR:-/var/lib/auto-bughunter/updates}"
TOOL_UPDATER_MANIFEST="${TOOL_UPDATER_MANIFEST:-/etc/auto-bughunter/tool-updater/manifest.json}"
TOOL_UPDATER_HTTP_TIMEOUT="${TOOL_UPDATER_HTTP_TIMEOUT:-15}"

REPORT_PATH="${TOOL_UPDATES_DIR}/report.json"
REPORT_TMP="${REPORT_PATH}.part"

mkdir -p "${TOOL_UPDATES_DIR}"

now() { date -u +%FT%TZ; }

log() { printf '[tool-updater %s] %s\n' "$(now)" "$*"; }

# --- 1. Nuclei templates -------------------------------------------------
nuclei_status="skipped"
nuclei_detail="TOOL_UPDATER_SKIP_NUCLEI=1"

if [[ "${TOOL_UPDATER_SKIP_NUCLEI:-0}" != "1" ]]; then
    mkdir -p "${NUCLEI_TEMPLATES_DIR}"
    log "refreshing nuclei templates into ${NUCLEI_TEMPLATES_DIR}"
    # `-update-templates` exits 0 even when offline, so capture stderr to
    # surface the underlying problem in the report.
    nuclei_log="$(mktemp)"
    if nuclei -ut -ud "${NUCLEI_TEMPLATES_DIR}" -silent >"${nuclei_log}" 2>&1; then
        nuclei_status="ok"
        nuclei_detail="$(tail -n 1 "${nuclei_log}" | tr -d '\r' || true)"
        log "nuclei templates updated: ${nuclei_detail:-<no output>}"
    else
        nuclei_status="error"
        nuclei_detail="$(tail -n 5 "${nuclei_log}" | tr '\n' ' ' | tr -d '\r')"
        log "nuclei template update failed: ${nuclei_detail}"
    fi
    rm -f "${nuclei_log}"
fi

# --- 2. Version checks against GitHub Releases --------------------------
# `tools_json` accumulates per-tool result objects. We start from an empty
# array so jq can keep appending even when the manifest is missing.
tools_json='[]'
summary_outdated=0
summary_current=0
summary_failed=0

if [[ "${TOOL_UPDATER_SKIP_VERSION:-0}" != "1" ]]; then
    if [[ ! -f "${TOOL_UPDATER_MANIFEST}" ]]; then
        log "manifest ${TOOL_UPDATER_MANIFEST} not found; skipping version checks"
    else
        # Build the curl auth header lazily so an empty token doesn't end
        # up as `Authorization: Bearer ` (GitHub rejects that as malformed).
        # Note: under `set -u` an unset array expanded with `${arr[@]}` is
        # an error, so we use the `+` form to expand to nothing when empty.
        auth_args=()
        if [[ -n "${GITHUB_TOKEN:-}" ]]; then
            auth_args=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
        fi

        # Iterate the manifest with jq -c so each line is an independent
        # JSON object (no shell-quoting headaches with `eval`).
        while IFS= read -r entry; do
            name="$(jq -r '.name'    <<<"${entry}")"
            repo="$(jq -r '.repo'    <<<"${entry}")"
            pinned="$(jq -r '.current' <<<"${entry}")"

            url="https://api.github.com/repos/${repo}/releases/latest"
            body="$(mktemp)"
            http_code="$(curl -sS \
                --max-time "${TOOL_UPDATER_HTTP_TIMEOUT}" \
                --retry 2 --retry-delay 2 \
                "${auth_args[@]+"${auth_args[@]}"}" \
                -H "Accept: application/vnd.github+json" \
                -H "User-Agent: auto-bughunter-tool-updater" \
                -o "${body}" -w '%{http_code}' \
                "${url}" || echo "000")"

            latest=""
            published_at=""
            html_url=""
            error=""
            status="unknown"

            if [[ "${http_code}" == "200" ]]; then
                latest="$(jq -r '.tag_name // ""'     "${body}")"
                published_at="$(jq -r '.published_at // ""' "${body}")"
                html_url="$(jq -r '.html_url // ""'   "${body}")"
                # Normalise both versions (drop leading `v`, lower-case)
                # for the equality check, but keep the original strings in
                # the report so consumers can render them verbatim.
                norm_pinned="$(echo "${pinned}" | sed 's/^[vV]//')"
                norm_latest="$(echo "${latest}" | sed 's/^[vV]//')"
                if [[ -z "${latest}" ]]; then
                    status="error"
                    error="github returned no tag_name"
                    summary_failed=$((summary_failed + 1))
                elif [[ "${norm_pinned}" == "${norm_latest}" ]]; then
                    status="current"
                    summary_current=$((summary_current + 1))
                else
                    status="outdated"
                    summary_outdated=$((summary_outdated + 1))
                fi
            else
                status="error"
                error="HTTP ${http_code} from ${url}"
                summary_failed=$((summary_failed + 1))
            fi
            rm -f "${body}"

            tools_json="$(jq -c \
                --arg name "${name}" \
                --arg repo "${repo}" \
                --arg current "${pinned}" \
                --arg latest "${latest}" \
                --arg status "${status}" \
                --arg published_at "${published_at}" \
                --arg html_url "${html_url}" \
                --arg error "${error}" \
                '. + [{
                    name: $name,
                    repo: $repo,
                    current: $current,
                    latest: $latest,
                    status: $status,
                    publishedAt: $published_at,
                    releaseUrl: $html_url,
                    error: $error
                }]' <<<"${tools_json}")"

            log "  ${name}: pinned=${pinned} latest=${latest:-?} status=${status}${error:+ (${error})}"
        done < <(jq -c '.tools[]' "${TOOL_UPDATER_MANIFEST}")
    fi
else
    log "TOOL_UPDATER_SKIP_VERSION=1; skipping version checks"
fi

# --- 3. Assemble the report ---------------------------------------------
jq -n \
    --arg generated_at "$(now)" \
    --arg nuclei_status "${nuclei_status}" \
    --arg nuclei_detail "${nuclei_detail}" \
    --argjson tools "${tools_json}" \
    --argjson outdated "${summary_outdated}" \
    --argjson current "${summary_current}" \
    --argjson failed "${summary_failed}" \
    '{
        generatedAt: $generated_at,
        nucleiTemplates: { status: $nuclei_status, detail: $nuclei_detail },
        summary: { outdated: $outdated, current: $current, failed: $failed },
        tools: $tools
    }' >"${REPORT_TMP}"
mv "${REPORT_TMP}" "${REPORT_PATH}"

log "wrote report to ${REPORT_PATH}"
log "summary: ${summary_outdated} outdated, ${summary_current} current, ${summary_failed} failed"

# Exit 0 even when individual checks failed — a transient GitHub blip
# shouldn't keep the rest of the platform from coming up. Persistent
# failures are visible in the report and via `GET /api/tools/updates`.
exit 0
