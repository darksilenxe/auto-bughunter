#!/bin/sh
# ---------------------------------------------------------------------------
# Kiterunner sidecar entrypoint.
#
# 1. On first start (or after the cache is wiped), download every wordlist
#    listed in the Assetnote manifest at https://wordlists.assetnote.io/data
#    into $WORDLIST_DIR/<category>/<filename>.
# 2. Drop a `.assetnote-sync.done` sentinel so subsequent restarts skip the
#    download and become near-instant.
# 3. Hand off to `tail -f /dev/null` so the container stays alive for
#    `docker compose exec -T kiterunner kr ...` calls from the backend.
#
# Set ASSETNOTE_FORCE_SYNC=1 to force a re-download even if the sentinel
# exists. Set ASSETNOTE_SKIP_SYNC=1 to skip the download entirely (useful
# for offline environments where the wordlists are already mounted in).
# ---------------------------------------------------------------------------

set -eu

WORDLIST_DIR="${WORDLIST_DIR:-/wordlists}"
MANIFEST_URL="${ASSETNOTE_MANIFEST_URL:-https://wordlists.assetnote.io/data}"
SENTINEL="${WORDLIST_DIR}/.assetnote-sync.done"

mkdir -p "${WORDLIST_DIR}"

should_sync=1
if [ "${ASSETNOTE_SKIP_SYNC:-}" = "1" ]; then
    should_sync=0
elif [ -f "${SENTINEL}" ] && [ "${ASSETNOTE_FORCE_SYNC:-}" != "1" ]; then
    should_sync=0
fi

if [ "${should_sync}" = "1" ]; then
    echo "kiterunner-sidecar: syncing Assetnote wordlists into ${WORDLIST_DIR}"
    tmp_manifest="$(mktemp)"
    trap 'rm -f "${tmp_manifest}"' EXIT

    if ! curl -fSL --retry 3 --retry-delay 5 -o "${tmp_manifest}" "${MANIFEST_URL}"; then
        echo "kiterunner-sidecar: WARNING: failed to fetch manifest from ${MANIFEST_URL}; continuing without wordlists" >&2
    else
        # The manifest is a JSON object keyed by category (e.g. "automated",
        # "manual", "kiterunner", "miscellaneous"). Each category is an array
        # of entries with at least a `download` field. We extract every
        # category/url pair as `<category>\t<url>` so we can preserve the
        # upstream layout on disk.
        downloads="$(jq -r '
            to_entries[]
            | .key as $cat
            | .value
            | (if type == "array" then . else [] end)
            | .[]
            | select(type == "object")
            | select(.download != null)
            | "\($cat)\t\(.download)"
        ' "${tmp_manifest}" 2>/dev/null || true)"

        if [ -z "${downloads}" ]; then
            echo "kiterunner-sidecar: WARNING: manifest produced no download URLs; the upstream schema may have changed" >&2
        else
            total="$(printf '%s\n' "${downloads}" | wc -l | tr -d ' ')"
            i=0
            # `printf | while read` runs in a subshell on POSIX sh, which is
            # fine here — we only need counters for logging.
            printf '%s\n' "${downloads}" | while IFS="$(printf '\t')" read -r category url; do
                i=$((i + 1))
                [ -n "${url}" ] || continue
                filename="$(basename "${url}")"
                # Strip any query string from the filename.
                filename="${filename%%\?*}"
                target_dir="${WORDLIST_DIR}/${category}"
                target="${target_dir}/${filename}"
                mkdir -p "${target_dir}"
                if [ -s "${target}" ] && [ "${ASSETNOTE_FORCE_SYNC:-}" != "1" ]; then
                    continue
                fi
                printf 'kiterunner-sidecar: [%d/%s] %s/%s\n' "${i}" "${total}" "${category}" "${filename}"
                if ! curl -fSL --retry 3 --retry-delay 5 -o "${target}.part" "${url}"; then
                    echo "kiterunner-sidecar: WARNING: failed to download ${url}" >&2
                    rm -f "${target}.part"
                    continue
                fi
                mv "${target}.part" "${target}"
            done
            echo "kiterunner-sidecar: sync complete"
        fi
    fi

    # Always mark the sync attempt — partial caches are fine, and the user
    # can re-run with ASSETNOTE_FORCE_SYNC=1 to retry. The temp manifest
    # is cleaned up by the EXIT trap installed above.
    : > "${SENTINEL}"
else
    echo "kiterunner-sidecar: ${SENTINEL} present (or ASSETNOTE_SKIP_SYNC=1); skipping Assetnote sync"
fi

# Keep PID 1 alive so the backend can `docker compose exec -T kiterunner kr`.
exec tail -f /dev/null
