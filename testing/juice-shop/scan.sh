#!/usr/bin/env bash
# Submit an authorized Auto Bughunter scan against the in-cluster Juice Shop
# instance and poll the API until the job finishes. Run from the repo root
# AFTER the stack is up:
#
#   docker compose -f docker-compose.yml \
#                  -f testing/juice-shop/docker-compose.juiceshop.yml \
#                  up --build -d
#   ./testing/juice-shop/scan.sh
#
# Optional environment overrides:
#   API_BASE         Backend API base URL (default: http://localhost:8080)
#   API_KEY          Backend API key (default: auto-bughunter-juice-shop-test-key)
#   TARGET_URL       Target URL to scan (default: http://juice-shop:3000)
#   POLL_TIMEOUT     Max seconds to wait for completion (default: 1200)
#   POLL_INTERVAL    Seconds between status polls (default: 10)
#   OUTPUT_DIR       Directory for saved artifacts (default: testing/juice-shop/out)
#   CRAWL_MAX_PAGES  Crawl budget passed to the scanner (default: 25)

set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8080}"
API_KEY="${API_KEY:-auto-bughunter-juice-shop-test-key}"
TARGET_URL="${TARGET_URL:-http://juice-shop:3000}"
POLL_TIMEOUT="${POLL_TIMEOUT:-1200}"
POLL_INTERVAL="${POLL_INTERVAL:-10}"
OUTPUT_DIR="${OUTPUT_DIR:-testing/juice-shop/out}"
CRAWL_MAX_PAGES="${CRAWL_MAX_PAGES:-25}"

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v jq   >/dev/null 2>&1 || { echo "jq is required (apt-get install jq)" >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"

wait_for() {
  local name="$1" url="$2" deadline=$((SECONDS + 120))
  echo "[*] waiting for $name ($url)..."
  while (( SECONDS < deadline )); do
    if curl -fsS -o /dev/null --max-time 5 "$url"; then
      echo "[+] $name is ready"
      return 0
    fi
    sleep 3
  done
  echo "[-] timed out waiting for $name at $url" >&2
  exit 1
}

wait_for "backend"    "${API_BASE}/api/health"
wait_for "juice-shop" "http://localhost:3030/"

idem_key="juice-shop-$(date -u +%Y%m%dT%H%M%SZ)"

read -r -d '' BODY <<JSON || true
{
  "target": "${TARGET_URL}",
  "idempotencyKey": "${idem_key}",
  "programName": "Juice Shop Test Harness",
  "programPolicyVersion": "$(date -u +%Y-%m-%d)",
  "programScopeProfile": {
    "includeHosts": ["juice-shop"],
    "programRules": ["Authorized internal test against bundled OWASP Juice Shop"]
  },
  "authProfile": {
    "headers": {"X-Auto-Bughunter-Test": "juice-shop-harness"},
    "userAgent": "AutoBughunter/JuiceShopHarness"
  },
  "options": {
    "useNucleiIntegration": false,
    "useZapBaselineIntegration": false,
    "crawlMaxPages": ${CRAWL_MAX_PAGES}
  }
}
JSON

echo "[*] submitting scan against ${TARGET_URL}"
create_resp="$(curl -fsS -X POST -H 'Content-Type: application/json' \
  -H "X-API-Key: ${API_KEY}" \
  --data "$BODY" "${API_BASE}/api/scan")"
echo "$create_resp" | jq . > "${OUTPUT_DIR}/scan-create.json"

scan_id="$(echo "$create_resp" | jq -r '.id // .scanId // empty')"
if [[ -z "$scan_id" ]]; then
  echo "[-] failed to obtain scan id from response:" >&2
  echo "$create_resp" >&2
  exit 1
fi
echo "[+] scan id: ${scan_id}"

deadline=$((SECONDS + POLL_TIMEOUT))
status="queued"
while (( SECONDS < deadline )); do
  job="$(curl -fsS -H "X-API-Key: ${API_KEY}" "${API_BASE}/api/scan/${scan_id}" || true)"
  if [[ -n "$job" ]]; then
    status="$(echo "$job" | jq -r '.status // empty')"
    echo "[*] $(date -u +%H:%M:%S) status=${status}"
    case "$status" in
      completed|failed|error|cancelled|canceled)
        echo "$job" | jq . > "${OUTPUT_DIR}/scan-${scan_id}.json"
        break
        ;;
    esac
  fi
  sleep "$POLL_INTERVAL"
done

if [[ "$status" != "completed" ]]; then
  echo "[-] scan did not complete cleanly (final status: ${status:-unknown})" >&2
  exit 2
fi

echo "[+] scan completed; summarizing findings"
jq -r '
  .findings // [] |
  group_by(.severity // "unknown") |
  map({severity: (.[0].severity // "unknown"), count: length}) |
  .[] | "  \(.severity): \(.count)"
' "${OUTPUT_DIR}/scan-${scan_id}.json" || true

echo "[*] downloading Markdown report"
curl -fsS -H "X-API-Key: ${API_KEY}" \
  "${API_BASE}/api/report/${scan_id}?format=md&type=pentest" \
  -o "${OUTPUT_DIR}/report-${scan_id}.md" \
  && echo "[+] report saved: ${OUTPUT_DIR}/report-${scan_id}.md" \
  || echo "[!] failed to fetch markdown report"

echo "[+] artifacts in: ${OUTPUT_DIR}"
