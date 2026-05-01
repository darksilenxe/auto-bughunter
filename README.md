# Auto Bughunter (Authorized Security Testing)

[![E2E - Juice Shop Harness](https://github.com/darksilenxe/auto-bughunter/actions/workflows/e2e-juice-shop.yml/badge.svg)](https://github.com/darksilenxe/auto-bughunter/actions/workflows/e2e-juice-shop.yml)
[![QA - Container Builds](https://github.com/darksilenxe/auto-bughunter/actions/workflows/qa-container-builds.yml/badge.svg)](https://github.com/darksilenxe/auto-bughunter/actions/workflows/qa-container-builds.yml)

A Dockerized starter platform for **authorized** web application security assessments.

See the implementation roadmap: [ROADMAP.md](./ROADMAP.md)

## Important Use Policy

This project is designed for defensive testing on systems you own or are explicitly authorized to test.
Do not scan third-party systems without written permission.

## Stack

- Backend: Go API (`net/http`) with modular scanners
- Frontend: React + Vite (JavaScript)
- Headless browser checks: `chromedp` against a `chromium` sidecar over the DevTools protocol
- Containerization: Docker + Docker Compose, with heavy security tools split into per-tool sidecars (see [Architecture](#architecture))
- AI summary: OpenAI-compatible Chat Completions API
- Curated security knowledge retrieval sidecar for cited AppSec context

## Features

- Asynchronous scan jobs with multi-agent orchestration
- PostgreSQL-backed scan persistence
- Optional Neo4j-backed attack-graph persistence for visualization replay
- Authenticated scan profiles (headers, cookies, basic auth, user-agent)
- Multi-agent architecture:
  - **Reconnaissance Agent**: DNS resolution, service discovery, tech stack probing
  - **Scanning Agent**: Core security checks (headers, cookies, TLS, headless browser)
  - **Wordlist Agent**: Directory, subdomain, and API endpoint fuzzing
  - **Analysis Agent**: Finding deduplication, severity-based ranking
  - **ML Triage Agent**: Deterministic risk scoring + exploitability estimation across all findings
  - **Attack Path Agent**: Cross-category correlation to infer likely multi-step attack chains
  - **False Positive Review Agent**: Confidence-based shortlist for analyst verification
  - **Remediation Planner Agent**: AI-assisted prioritized remediation sequence generation
  - **Reporting Agent**: Executive summaries, top-risk identification
- Built-in checks:
  - Security headers
  - Cookie flags
  - TLS basics
  - Headless form discovery (for review)
  - **Wordlist-based enumeration**:
    - Common directories (admin, api, config, uploads, etc.)
    - Common subdomains (admin, api, staging, cdn, etc.)
    - Common API endpoints (/api/v1, /graphql, /.well-known/openid-configuration, etc.)
- Optional integrations behind feature flags:
  - Nuclei
  - OWASP ZAP Baseline
  - XSSMap (LLM-assisted XSS, requires `ALLOW_DESTRUCTIVE_CHECKS=true`)
  - ShuffleDNS
  - Certificate Transparency (crt.sh)
  - Amass (native Go passive discovery)
- Optional AI-generated executive summary for findings
- Offline AI reasoner (local analysis when no API available)

## Quick Start

1. Copy env file:

```bash
cp .env.example .env
```

2. Set your allowed targets, database settings, and optional AI/integration settings in `.env`.

3. Run:

```bash
docker compose up --build
```

Optional local AI runtime + UI:

```bash
docker compose --profile ai up --build
```

Then set in `.env`:

```bash
AI_API_BASE=http://ollama:11434/v1
AI_MODEL=llama3.1:8b
AI_API_KEY=
# Optional larger coding-focused model used by the orchestration planner
AI_CODING_MODEL=codellama
# Optional overrides (defaults to AI_API_BASE / AI_API_KEY when omitted)
AI_CODING_API_BASE=
AI_CODING_API_KEY=
# Optional second local Ollama model pre-pulled on startup
OLLAMA_SECONDARY_MODEL=codellama
```

4. Open:

- Frontend: http://localhost:3000
- Backend health: http://localhost:8080/api/health

## Command-line interface

The backend now includes a small operator CLI under
`./backend/cmd/autobughunter`.
It is focused on tool readiness/updates plus ML dataset and inference
workflows, and acts as a thin client over the existing backend and ML service
HTTP contracts.

### Running it from source

Build or run it from the backend module:

```bash
cd ./backend
go build ./cmd/autobughunter
# or:
go run ./cmd/autobughunter --help
```

### Using it as a standalone binary

Yes — you can run it as a standalone command-line binary after building or
installing it. For example:

```bash
cd ./backend
mkdir -p ../bin
go build -o ../bin/autobughunter ./cmd/autobughunter
../bin/autobughunter help
```

Or install it into your Go bin directory:

```bash
cd ./backend
go install ./cmd/autobughunter
autobughunter help
```

The binary is standalone in the sense that it does not need the frontend, but
it is still a thin client:

- `scan start`
- `scan get`
- `scan run`
- `tools health`
- `tools updates`
- `ml dataset export`

require a reachable backend API.

- `ml score-findings`
- `ml attack-paths`
- `ml remediation-plan`
- `ml false-positive-candidates`

require a reachable ML service API.

So you can copy the binary anywhere and run it directly, as long as the target
backend and/or ML service URLs, auth, and network access are available.

The new `scan` commands make the standalone binary usable as a GUI-less,
automation-friendly scanner by submitting jobs directly to the backend API and,
for `scan run`, polling until a terminal status is reached.

### Supported commands

```text
autobughunter scan start
autobughunter scan get
autobughunter scan run
autobughunter tools health
autobughunter tools updates
autobughunter ml dataset export
autobughunter ml score-findings
autobughunter ml attack-paths
autobughunter ml remediation-plan
autobughunter ml false-positive-candidates
```

### Shared configuration

Flags are available per command, and these environment variables provide
defaults:

- `AUTOBUGHUNTER_BACKEND_URL` (default `http://localhost:8080`)
- `AUTOBUGHUNTER_ML_URL` (falls back to `ML_SERVICE_URL`, then defaults to `http://localhost:8090`)
- `AUTOBUGHUNTER_API_KEY` (falls back to `BOOTSTRAP_ADMIN_API_KEY`)
- `AUTOBUGHUNTER_WORKSPACE_ID`
- `AUTOBUGHUNTER_SIDECAR_AUTH_TOKEN` (falls back to `SIDECAR_AUTH_TOKEN`)

The backend-facing commands send `X-API-Key` and optional
`X-Workspace-ID`, matching the existing `/api/*` authentication model.
Direct ML-service commands send `Authorization: Bearer <token>` when a sidecar
token is configured.

For standalone scans, use either:

- `-target <url>` for simple CLI-driven runs
- `-input <request.json|->` to submit a full `ScanRequest` payload from a file
  or stdin

Common scan flags:

- `-idempotency-key`
- `-automation-mode`
- `-passive-only`
- `-aggressive-exploitation`
- `-poll-interval` (scan run)
- `-wait-timeout` (scan run)

### Examples

Check tool readiness from a local stack:

```bash
cd ./backend
AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
go run ./cmd/autobughunter tools health -format text
```

Run a simple GUI-less standalone scan and wait for completion:

```bash
AUTOBUGHUNTER_BACKEND_URL="http://localhost:8080" \
AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
./bin/autobughunter scan run \
  -target "https://demo.owasp-juice.shop" \
  -automation-mode conservative \
  -passive-only \
  -format text
```

Run the embedded standalone utility directly from the Go main package and enable
the full scan toolset in one command:

```bash
cd ./backend
go run ./cmd/standalone scan run \
  -target "https://demo.owasp-juice.shop" \
  -full-scan \
  -allow-destructive \
  -use-ml-triage \
  -use-attack-paths \
  -use-false-positive-review \
  -use-remediation-planner \
  -format text
```

For a Go-only toolchain preset, replace `-full-scan` with `-all-go-tools`.
`-allow-destructive` is required for destructive native Go checks such as
Nikto and SQLMap, and for XSSMap when `-full-scan` is used.

Submit a richer automated scan request from JSON and fetch it later:

```bash
cat > /tmp/scan-request.json <<'EOF'
{
  "target": "https://demo.owasp-juice.shop",
  "options": {
    "automationMode": "conservative",
    "passiveOnly": true
  }
}
EOF

AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
./bin/autobughunter scan start -input /tmp/scan-request.json -format text

AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
./bin/autobughunter scan get -id <scan-id> -format text
```

Check tool readiness with a previously built standalone binary:

```bash
AUTOBUGHUNTER_BACKEND_URL="http://localhost:8080" \
AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
./bin/autobughunter tools health -format text
```

Fetch the sidecar-generated tool update report:

```bash
cd ./backend
AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
go run ./cmd/autobughunter tools updates
```

Export a sanitized ML training dataset from the backend:

```bash
cd ./backend
AUTOBUGHUNTER_API_KEY="$BOOTSTRAP_ADMIN_API_KEY" \
go run ./cmd/autobughunter ml dataset export -limit 250 > /tmp/engagements.dataset.json
```

Call the backend directly from a standalone binary installed on your `PATH`:

```bash
AUTOBUGHUNTER_BACKEND_URL="https://backend.example.internal" \
AUTOBUGHUNTER_API_KEY="your-api-key" \
AUTOBUGHUNTER_WORKSPACE_ID="workspace-a" \
autobughunter ml dataset export -limit 100
```

Score findings by piping JSON directly to the ML service:

```bash
cat findings.json | \
  (cd ./backend && go run ./cmd/autobughunter \
    ml score-findings \
    -ml-base http://localhost:8090 \
    -sidecar-token "$SIDECAR_AUTH_TOKEN" \
    -input -)
```

Call the ML service directly with a standalone binary:

```bash
AUTOBUGHUNTER_ML_URL="http://localhost:8090" \
AUTOBUGHUNTER_SIDECAR_AUTH_TOKEN="$SIDECAR_AUTH_TOKEN" \
./bin/autobughunter ml score-findings -input findings.json
```

Generate attack paths or remediation guidance from a file containing either a
full request object or a bare findings array:

```bash
(cd ./backend && go run ./cmd/autobughunter \
  ml attack-paths -ml-base http://localhost:8090 -input ../findings.json)

(cd ./backend && go run ./cmd/autobughunter \
  ml remediation-plan -ml-base http://localhost:8090 -input ../findings.json -limit 3 -format text)
```

## Metasploit RPC customization

The Metasploit agent supports optional RPC module execution when `MSF_RPC_URL`
and `MSF_RPC_PASSWORD` are set.

- `MSF_RPC_ENABLE_LESS_SAFE_MODULES=true` enables extra high-risk exploit modules.
- `MSF_RPC_MODULE_TEMPLATE_FILE=/app/backend/templates/metasploit_rpc_modules.template.json`
  lets you load your own module list template.
- Use `backend/templates/metasploit_rpc_modules.template.json` as the starter template.
- Template placeholders are auto-expanded: `{{RHOSTS}}`, `{{RPORT}}`, `{{SSL}}`, `{{TARGETURI}}`.

## Architecture

The backend container is intentionally slim — it ships only the Go server
binary plus the Docker CLI. Each heavy security dependency runs in its own
Docker Compose sidecar:

| Sidecar service    | Image                              | What the backend uses it for                                                            |
| ------------------ | ---------------------------------- | --------------------------------------------------------------------------------------- |
| `zap`              | `zaproxy/zap-stable:2.17.0`        | OWASP ZAP daemon + `zap-baseline.py` passive scan                                       |
| `nuclei`           | `projectdiscovery/nuclei:v3.8.0`   | Nuclei templated vulnerability scanning                                                 |
| `chromium`         | `chromedp/headless-shell:latest`   | Headless browser crawl/screenshot via DevTools (9222)                                   |
| `projectdiscovery` | local build (see `sidecars/`)      | Shared suite: `subfinder` v2.13.0, `httpx` v1.9.0, `cloudlist` v1.4.0, `naabu` v2.5.0, `dnsx` v1.2.3, `shuffledns` v1.2.1, `katana` v1.5.0, `tlsx` v1.2.2, `cdncheck` v1.2.31, `asnmap` v1.1.1, `vulnx` v2.0.1 |
| `ffuf`             | `secsi/ffuf:2.1.0`                 | Web content fuzzing (consumes wordlist via the `shared_tmp` volume; also has read-only `/wordlists` from the kiterunner sidecar) |
| `gobuster`         | `ghcr.io/oj/gobuster`              | Directory brute-forcing (consumes wordlist via the `shared_tmp` volume; also has read-only `/wordlists` from the kiterunner sidecar) |
| `kiterunner`       | local build (see `sidecars/`)      | Assetnote `kr` API content discovery — pre-downloads every wordlist from `wordlists.assetnote.io` into the shared `assetnote_wordlists` volume on first start |
| `tool-updater`     | local build (see `sidecars/`)      | One-shot service that runs on every `docker compose up`: refreshes the `nuclei_templates` volume and queries GitHub Releases for every pinned tool, writing a JSON report consumed by `GET /api/tools/updates`. Re-run on demand via `docker compose run --rm tool-updater` |
| `sqlmap`           | `parrotsec/sqlmap`                 | SQL injection probing — keeps Python out of the backend image                           |
| `nikto`            | `ghcr.io/sullo/nikto`              | Web server scanner — keeps Perl out of the backend image                                |
| `wpscan`           | `wpscanteam/wpscan`                | WordPress scanner — keeps Ruby out of the backend image                                 |
| `xssmap`           | local build (see `sidecars/xssmap/`) | Third-party LLM-assisted XSS scanner ([XSSMap](https://github.com/Sh3llholic/XSSMap), GPL-3.0). Bundled as an external tool only — source is not vendored. Reuses the local `ollama` service via `XSSMAP_OLLAMA_URL`. Per-scan opt-in via `useXssMapIntegration` and gated by `ALLOW_DESTRUCTIVE_CHECKS=true`. |
| `agents`           | local build (see `agents/`)        | Autonomous agent learner (HTTP, port 8091)                                              |
| `ml-service`       | local build (see `ml-service/`)    | ML triage / classifier service (HTTP, port 8090)                                        |
| `security-knowledge` | local build (see `security-knowledge/`) | Retrieval-only security context service with curated citations (HTTP, port 8092)    |
| `neo4j`            | `neo4j:5.26.1`                     | Optional graph database storing attack-graph snapshots returned to the frontend (Bolt 7687 / HTTP 7474) |

The backend container is the **single orchestrator** of the stack: it is
the only service that issues HTTP calls to tool sidecars (HTTP mode) or
`docker compose exec` into the CLI sidecars (exec mode), and the only
service that talks to `agents` / `ml-service` / `security-knowledge`. No
sidecar talks to another sidecar.

Two integration paths:

1. **CLI tools (`nuclei`, `zap-baseline.py`)** — the backend image installs
   thin shim scripts under `/usr/local/bin` (see
   `backend/scripts/shims/`) that `exec docker compose exec -T <svc> <tool>
   "$@"` into the matching sidecar. The Go scanner's existing
   `exec.LookPath(...)` + stdout parsing keeps working unchanged.
2. **Headless Chromium** — the Go scanner attaches to the `chromium`
   sidecar over the DevTools protocol via `chromedp.NewRemoteAllocator`
   when `CHROME_REMOTE_URL` is set (defaults to
   `http://chromium:9222`).

### Docker socket requirement

The default `docker-compose.yml` does **not** mount the host Docker
socket. The default deployment uses HTTP mode (see `.env.example`:
`USE_HTTP_TOOL_SERVICES=true`), where each tool sidecar exposes an HTTP
endpoint and the backend talks to it directly. No Docker socket
required.

The backend can communicate with tool sidecars in two modes:

#### 1. HTTP Mode (Default, No Docker Socket)

Set `USE_HTTP_TOOL_SERVICES=true` in `.env` (this is the default in
`.env.example`). Tool sidecars (nuclei-service, etc.) expose HTTP
endpoints that the backend calls directly. This eliminates the need
for Docker socket access entirely.

**Benefits:**
- No root-equivalent Docker socket access required
- Better security isolation between containers
- Works in Kubernetes and other orchestrators
- Easier to scale horizontally
- Container-orchestration agnostic

#### 2. Exec Mode (Opt-in, Requires Docker Socket)

When `USE_HTTP_TOOL_SERVICES=false`, shim scripts call
`docker compose exec -T <svc> <tool>` into CLI tool sidecars. This requires
the backend container to have `/var/run/docker.sock` bind-mounted, which
is intentionally **not** done by the default compose file. Layer the
opt-in override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.exec.yml up
```

The override sets `USE_HTTP_TOOL_SERVICES=false` and adds the socket
mount in one place.

**This is effectively root-equivalent on the host** — fine for self-hosted
single-tenant scanner usage, but not appropriate for multi-tenant deployments.

To opt out entirely (disable both modes), set `SIDECAR_EXEC_DISABLE=1`. The
Go scanner will then report the standard `<tool>-binary-missing` finding for
any integration that was enabled but cannot find its tool, and the rest of
the scan will run unaffected.

#### Migration Path

The codebase supports both modes simultaneously for gradual migration:

1. **Phase 1 (current)**: Nuclei and ZAP HTTP wrapper services are available.
   `USE_HTTP_TOOL_SERVICES=true` uses HTTP mode for those integrations.

2. **Phase 2 (future)**: Additional HTTP wrappers will be added for other
   tools (zap, ffuf, gobuster, etc.) following the same pattern as
   `sidecars/nuclei-service/`.

3. **Phase 3 (future)**: Once all critical tools have HTTP wrappers, exec
   mode can be fully deprecated and Docker socket access removed.

## API

### `POST /api/scan`

Body:

```json
{
  "target": "https://example.com",
  "idempotencyKey": "scan-example-2026-04-09T14:00",
  "authProfile": {
    "loginUrl": "https://example.com/login",
    "username": "user@example.com",
    "password": "secret",
    "loginSteps": [
      {"action": "fill", "selector": "#email", "value": "{{username}}"},
      {"action": "fill", "selector": "#password", "value": "{{password}}"},
      {"action": "click", "selector": "button[type='submit']"},
      {"action": "wait", "waitMillis": 1200}
    ],
    "headers": {"Authorization": "Bearer ..."},
    "cookies": {"sessionid": "..."},
    "userAgent": "Mozilla/5.0",
    "basicAuthUsername": "scanner",
    "basicAuthPassword": "secret"
  },
  "authProfiles": [
    {
      "roleName": "admin",
      "priority": 1,
      "authProfile": {
        "cookies": {"sessionid": "..."}
      }
    }
  ],
  "programName": "Example Program",
  "programPolicyVersion": "2026-04-01",
  "disallowedTestTypes": ["sqlmap", "ffuf"],
  "programScopeProfile": {
    "includeHosts": ["example.com", "*.example.com"],
    "excludeHosts": ["admin.example.com"],
    "excludePaths": ["/logout", "/billing"],
    "programRules": ["No destructive testing"]
  },
  "options": {
    "useNucleiIntegration": false,
    "useZapBaselineIntegration": false,
    "useXssMapIntegration": false,
    "supplementalResourceUrls": [
      "https://docs.example-cdn.com/security.txt"
    ]
  }
}
```

`authProfile` is optional. Omit it, or send an empty object, to run an unauthenticated scan that only uses the target URL and scope/program data as provided.

### `GET /api/scan/{id}`

Returns job state and findings, including per-agent telemetry (`agentRuns`), structured decision data (`dashboard`, `nextActions`), ML recommendations (`modelRecommendations`), asset relationships (`assetLinks`), and an automated penetration test report (`automatedReport`) with findings/severities/how-found/commands-used.

### `GET /api/ml/engagements?limit=100`

Returns a sanitized, pseudonymized engagement dataset built from completed scans and related telemetry (including per-scan feedback outcomes) for offline/shadow ML training and evaluation.

### `POST /api/feedback`

Stores bug bounty outcome labels so prioritization can learn from accepted/rejected results.

```json
{
  "scanId": "scan-uuid",
  "findingId": "finding-id",
  "category": "headers",
  "title": "Missing security header",
  "programName": "Example Program",
  "outcome": "accepted",
  "payoutUsd": 150.0,
  "notes": "Accepted by triager"
}
```

### `POST /api/finding-verification`

Stores manual exploitability verification (`confirmed` / `rejected`) for a finding.

### `POST /api/suppressions`

Creates suppression/baseline rules (optional target scope, optional expiry) to hide accepted noise.

### `POST /api/automation/event`

Queues event-driven scans from CI/CD or asset discovery pipelines (`deploy`, `dependency_change`, `config_change`, `new_asset`).

Supports unattended ROI controls through scan options:

- `automationMode`: `safe` | `autonomous` | `aggressive`
- `minExpectedRoiUsd`: minimum expected ROI required for automated follow-up actions
- `dailyScanLimit` / `dailyRuntimeLimitMinutes` / `dailyProbeLimit`: hard daily workspace budgets

### `GET|POST|PUT|DELETE /api/automation/campaigns`

Persistent recurring campaign scheduler for unattended operation.

- `GET /api/automation/campaigns?activeOnly=true` lists campaigns for the caller workspace.
- `POST/PUT` upserts a campaign (`target`, `intervalMin`, optional auth/options/scope).
- `POST/PUT` also supports `scheduleType` (`interval|daily|weekly`), `scheduleValue`, `runWindow`, `blackoutWindows`, and `maxAttempts` for safer unattended dispatch.
- Active campaign upserts require `authorizationApproval` (`approvedBy`, `approverRole`, `approvedAt`, `signature`) plus at least one `authorizationEvidence` record (`type`, `label`, `uri` and/or `sha256`).
- `DELETE /api/automation/campaigns?id=<campaign-id>` deletes a campaign.

### `GET /api/automation/campaign-authorization-export?id=<campaign-id>`

Returns an immutable authorization evidence bundle for a campaign, including:

- signed approval metadata
- normalized evidence records
- `authorizationDigest` (stable SHA-256 digest over campaign authorization payload)
- `exportHash` (SHA-256 digest of the exported bundle)

### `GET|POST /api/automation/roi-overrides`

Stores per-workspace/per-program ROI overrides used by automation gating.

### `GET /api/automation/report`

Returns an executive automation report with scan trends, feedback quality metrics, ROI KPIs, and open automated ticket counts.

### `GET /api/automation/tickets`

Returns open auto-managed remediation tickets (optionally filtered by `?target=`).

### `GET /api/tools/health`

Returns scanner toolchain readiness (binary presence by category) to verify bug bounty execution coverage.

### Out-of-band (OAST) callback service

When `ENABLE_OAST=true`, the backend starts a second HTTP listener (default
port `9000`, configurable via `OAST_LISTEN_PORT`) that records inbound
interactions on `/<token>`. Set `OAST_PUBLIC_BASE_URL` to the externally
reachable URL of that listener (e.g. `http://oast.example.com:9000`) so
issued tokens have usable callback URLs.

The scanner uses these tokens to detect blind/out-of-band vulnerabilities
such as SSRF. Two OAST-driven SSRF probes are enabled by default whenever
OAST is configured:

- `oast-ssrf-headers` — injects the callback URL into 11 forwarding/origin
  headers (`X-Forwarded-For/Host`, `Forwarded`, `X-Original-URL`,
  `X-Rewrite-URL`, `X-Client-IP`, `X-Real-IP`, `Referer`,
  `X-HTTP-DestinationURL`, `CF-Connecting-IP`, `True-Client-IP`).
- `oast-ssrf-body-params` — POSTs the callback URL into common URL-bearing
  body fields (`url`, `callback`, `webhook`, `redirect`, `next`, `image`,
  `avatar`, `src`, …) using both `application/x-www-form-urlencoded` and
  `application/json` encodings against the target and runtime-discovered
  endpoints.

Findings include the captured interaction as evidence.

Two additional active probes run on every scan and do not require OAST:

- `active-xss-reflected` — injects an HTML-context marker into common
  reflective parameters (`q`, `search`, `query`, `s`, `keyword`, `name`,
  `title`, `msg`, …) across runtime-discovered endpoints and inspects
  the response body for unescaped reflection. Emits a single CWE-79
  finding.
- `active-sqli-error-based` — appends a single benign quote to common
  ID/lookup parameters and matches the response against stable database
  parser-error signatures (MySQL, PostgreSQL, MSSQL, Oracle, SQLite,
  JDBC/ODBC). Emits a single CWE-89 finding. No UNION/sleep/boolean
  payloads are sent.
- `subdomain-takeover` — for every concrete in-scope subdomain (from
  `scope.includeHosts` and runtime endpoint discovery, excluding the
  target host itself and wildcard patterns), GETs the host and matches
  the response body against a curated set of dangling-CNAME service
  fingerprints (AWS S3, GitHub Pages, Heroku, Shopify, Fastly, Surge,
  Tumblr, Bitbucket, Pantheon, Squarespace, Help Scout, Tilda,
  Unbounce). Emits a single CWE-1104 / OWASP A06 finding listing every
  confirmed unclaimed host.

When the request includes one or more `authProfiles` (role profiles), an
active **IDOR role-diff** probe (`idor-role-diff`) runs after the
per-role scans complete. It replays in-scope endpoints whose path
contains an opaque object identifier (numeric, UUID, or long hex) as
each identity (anonymous + baseline + each role) and emits a
CWE-639 / OWASP A01 finding when two identities receive equivalent
successful responses (matching status code and body length within 64
bytes). Anonymous-vs-authenticated parity is reported at high severity.

Admin API:

- `GET /api/oast/tokens[?scanId=...]` — list active tokens.
- `POST /api/oast/tokens` — issue a token. JSON body: `{"scanId":"...","label":"..."}` (both optional).
- `GET /api/oast/hits/{token}` — list recorded callbacks for a token.

OAST state is in-memory and per-token TTL'd (default 60 minutes); restart
the backend to clear all tokens. DNS-based interactions are intentionally
not handled here — only HTTP(S) callbacks to the listener are recorded.

## Reports

The reporting layer produces professional pen-test deliverables and bug-bounty
submissions in multiple formats. All endpoints are served under `/api/report/`.

| Endpoint | Description |
|----------|-------------|
| `GET /api/report/{scanId}` | Main report. Defaults to PDF for backward compatibility. |
| `GET /api/report/{scanId}?format=pdf\|md\|html\|json&type=pentest\|executive\|compliance` | Format / report-type negotiation via query string. |
| `POST /api/report/{scanId}` | Same as GET but accepts `ReportTemplateOptions` (company name, classification, contact, program handle, logo path, report type) in the JSON body for cover-page customization. Query-string parameters take precedence. |
| `GET /api/report/{scanId}/finding/{findingId}?format=md\|pdf\|json&platform=hackerone\|bugcrowd\|intigriti` | Single bug-bounty submission for one finding. Defaults to Markdown. The optional `platform` query adds a platform-specific submission banner. |
| `GET /api/report/{scanId}/bugbounty.zip?platform=hackerone\|bugcrowd\|intigriti` | Zip bundle containing one Markdown submission per finding plus a top-level `INDEX.md`. The optional `platform` query is forwarded to every submission file. |
| `GET /api/findings/duplicates?scanId={scanId}&threshold=0.6&priorLimit=50` | Deterministic duplicate detector: returns prior-scan findings that resemble the current scan's findings (similarity scored on category, CWE, normalized title, affected URL/host+path, and parameter). |

**Report types:**

- `pentest` (default): full pen-test deliverable with cover page, executive
  summary, scope & methodology, risk-rating methodology, findings grouped by
  severity (each with CVSS / CWE / OWASP / reproduction steps / impact /
  remediation / references), **Attack Paths** narratives chained from
  `Dashboard.TopAttackPaths`, **Remediation Priorities** ranked by severity-
  weighted impact reduction, **Per-Asset Rollup** pivoting findings by host,
  **What Changed Since Last Engagement** delta vs. the previous completed
  scan, **Visual Evidence** (inline screenshots harvested from the agent
  event stream), and an appendix listing tools, commands, audit trail,
  assets discovered, and the **Compliance Crosswalk** (PCI DSS / HIPAA /
  SOC 2 controls keyed off CWE/OWASP).
- `executive`: one-page summary intended for stakeholders, including the top
  remediation priorities and the trend vs. the previous engagement.
- `compliance`: focused PCI DSS v4.0 / HIPAA Security Rule / SOC 2 Common
  Criteria crosswalk. Empty cells indicate no deterministic mapping is
  available for the underlying CWE.

**Formats:**

`pdf` (default for `pentest`), `md` / `markdown`, `html`, `json`.

**Tamper-evident delivery:** every PDF, HTML, and Markdown report ends with a
SHA-256 hash of the canonical report data (the timestamp is excluded so the
same scan rendered twice produces the same hash). Reviewers can confirm two
deliverables came from the same underlying findings by comparing the hash.

### Sample bug-bounty submission

```markdown
# SQL injection in id parameter

## Summary

Error-based SQL injection detected.

## Vulnerability Details

- **Severity:** HIGH
- **CWE:** CWE-89
- **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
- **Asset:** https://example.com/users
- **Affected Parameter:** id

## Steps to Reproduce

1. Identify the vulnerable parameter listed in the finding evidence.
2. Send an HTTP request that injects a SQL meta-character (e.g. `'`) into that parameter.
3. Observe a database error in the response or a content/timing difference vs. the baseline.
4. Confirm exploitability by extracting a known value (e.g. `' OR '1'='1`).

## Impact

An attacker can read, modify, or destroy database contents and may achieve
remote code execution depending on the database engine configuration.

## Suggested Remediation

Use parameterized queries (prepared statements) for all database interactions.

## References

- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/89.html
- https://owasp.org/Top10/A03_2021-Injection/
```

## End-to-end test harness (OWASP Juice Shop)

A self-contained testing environment that brings up the full stack alongside
an authorized [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
target lives in [`testing/juice-shop/`](testing/juice-shop/README.md). It can
be used to validate that scanning, orchestration, and reporting are working
before pointing the platform at real targets.

```bash
cp testing/juice-shop/.env.juiceshop.example .env
docker compose \
  -f docker-compose.yml \
  -f testing/juice-shop/docker-compose.juiceshop.yml \
  up --build -d
./testing/juice-shop/scan.sh
```

## Planner offline replay harness

`backend/cmd/replayharness` replays recorded historical scans through a baseline
planner and a candidate planner and emits a JSON comparison report. It is
hermetic — no network or database — so it can be used in CI to score candidate
planning strategies against a baseline.

```bash
go run ./backend/cmd/replayharness \
  -input path/to/history.json \
  -baseline static \
  -candidate recorded \
  -output /tmp/replay-report.json
```

`history.json` is either a single object or an array of `replay.HistoricalRun`
objects (`scanId`, `target`, `availableAgents`, `runs[].agentName`, plus
optional `findings`, `metadata`, `options`, `scope`, `autonomyMemory`). The
`-baseline` and `-candidate` flags currently support `static` (registered agent
order) and `recorded` (oracle that follows the historical execution order).
The output report includes per-round planner decisions, per-run match rates,
aggregate `matchRate` / `firstChoiceMatchRate`, and a `delta` block summarising
candidate-minus-baseline improvement.

## Notes

- `authProfile` (headers/cookies/basic auth) is required for scan creation.
- If AI environment variables are missing or provider calls fail, the backend uses an offline local AI reasoner that ranks findings and proposes remediation steps.
- For OpenAI default (`https://api.openai.com/v1`), set `AI_API_KEY`; for local OpenAI-compatible containers (for example Ollama), API key can be blank.
- Set `AI_CODING_MODEL` to route AI orchestration/planning calls to a larger coding-focused model while keeping summaries on `AI_MODEL`.
- ML dataset generation strips/masks sensitive values (tokens/cookies/password-like data) and pseudonymizes URL/host identifiers before export.
- Job records are stored in PostgreSQL table `scans`.
- Per-scan asset inventory is stored in `scan_assets` and run events are stored in `scan_events`.
- Model recommendation artifacts are persisted in `scans.model_recommendations`.
- Finding records include confidence, source attribution, structured evidence fields, drift status, business tags, and exploitability metadata.
- Scan scope supports host wildcard patterns (`*.example.com`) and out-of-scope path prefixes.
- Scan creation and scanner execution enforce per-scan scope (target, integration expansion, and wordlist probes).
- Proxy replay supports optional per-request scope validation via `scope` on `POST /api/proxy/replay`.
- Burp-style proxy suite (HTTP History · Repeater · Intruder) is available in the frontend at `/proxy` when `ENABLE_PROXY=true`. The intercepting listener (default `:8081`) captures plain HTTP fully and HTTPS via optional TLS interception when a CA is configured. Set `PROXY_CA_CERT_FILE`, `PROXY_CA_KEY_FILE`, and `PROXY_CA_AUTOGENERATE=true` to have the backend self-sign a CA on first boot; download it from `GET /api/proxy/ca-certificate` (or the Configure Browser tab) and install in your browser/OS trust store. The Intruder fuzzer is exposed via `POST /api/proxy/intruder` and substitutes a marker (default `§`) in the URL/headers/body for each payload (capped at 200 per attack).
- When a previous completed scan exists for the same target, the job includes a monitoring finding summarizing newly observed issues.
- Optional automatic rescans can be scheduled per target with `options.rescanIntervalMinutes`.
- Program scope profiles can be merged into per-scan scope automatically with `programScopeProfile`.
- Disallowed test types can be enforced at request time with `disallowedTestTypes`.
- Role-based authenticated coverage can be expanded with `authProfiles` (multiple role sessions).
- Scanner request pacing/retry controls are available via `options.maxRetries`, `options.backoffMillis`, and `options.requestDelayMillis`.
- Scan creation supports idempotent deduplication via `idempotencyKey` field or `Idempotency-Key` HTTP header.
- Per-target rate limiting can be enforced with `options.targetRateLimitPerMinute`.
- Global concurrent scan budgeting can be configured via `GLOBAL_SCAN_BUDGET`.
- Outbound probe and proxy targets are protected by SSRF safety checks (localhost/private/link-local/metadata IP blocks).
- Runtime surface expansion now mines in-scope endpoint hints from response/DOM artifacts (including JS/OpenAPI/GraphQL-style markers) to increase attack-surface coverage.
- Scanner includes safe context-aware parameter probing to surface high-signal reflection/error paths for targeted follow-up testing.
- Multi-role scan runs now include role-diff findings that highlight role-specific behavior for authorization/IDOR validation.
- Stateful headless crawling can traverse multiple in-scope pages using `options.crawlMaxPages` (bounded) to improve authenticated coverage stability checks.
- Per-target concurrency can be constrained via `MAX_CONCURRENT_SCANS_PER_TARGET` (global default) or `options.maxPerTargetConcurrency`.
- Feedback outcomes submitted to `POST /api/feedback` are used by ML prioritization to favor historically accepted issue patterns.
- Manual finding verification from `POST /api/finding-verification` is returned on findings as exploitability verification status.
- Suppression rules from `POST /api/suppressions` support baseline/noise reduction with expiry.
- Policy-as-code release gating is evaluated per scan and can auto-block progression based on severity thresholds.
- Ticket lifecycle is fully automated: medium/high fingerprints are upserted as open tickets and auto-resolved when findings disappear.
- Tool-readiness checks run automatically and flag missing required binaries or category coverage gaps for bug bounty success.
- CI/CD and discovery systems can trigger immediate event-driven scans through `POST /api/automation/event`.
- Executive KPI summaries are available from `GET /api/automation/report`.
- Proxy artifacts are redacted by default and retained according to `PROXY_RETENTION_HOURS`.
- Optional notification hooks can be configured with `SCAN_WEBHOOK_URL` and `SLACK_WEBHOOK_URL` for high-confidence drift findings.
- Policy gate thresholds are configurable via `POLICY_GATE_HIGH_BLOCK` and `POLICY_GATE_MEDIUM_BLOCK`.
- ShuffleDNS and Certificate Transparency discovery are available as optional integrations behind `ENABLE_SHUFFLEDNS_INTEGRATION` and `ENABLE_CERTIFICATE_TRANSPARENCY_INTEGRATION`.
- Native Go Amass discovery is available behind `ENABLE_AMASS_INTEGRATION`.
- FFUF and Gobuster directory-discovery integrations are available behind `ENABLE_FFUF_INTEGRATION` and `ENABLE_GOBUSTER_INTEGRATION`.
- Destructive/high-impact checks are disabled by default; set `ALLOW_DESTRUCTIVE_CHECKS=true` only for explicitly authorized programs.
- Auth secrets are used only at execution time; persisted job data stores auth metadata summary only.
- Scans execute agents in sequence: reconnaissance → scanning → specialized security agents → wordlist → analysis → ML triage → attack path synthesis → false-positive review → remediation planning → reporting. Each agent enriches the findings pipeline.
- Autonomous orchestration is enabled by default (`ENABLE_AUTONOMOUS_ORCHESTRATION=true`): when an AI provider is configured, an AI planner picks the next agent to run after every step and may dynamically spawn additional agents (including repeating earlier stages) based on findings observed so far. The loop is bounded by `MAX_ORCHESTRATION_ROUNDS` (default `10`); when disabled or no AI key is set, the system falls back to the deterministic static pipeline above.
- ML agents can be controlled per deployment with `ENABLE_ML_TRIAGE_AGENT`, `ENABLE_ATTACK_PATH_AGENT`, `ENABLE_FALSE_POSITIVE_REVIEW_AGENT`, and `ENABLE_REMEDIATION_PLANNER_AGENT`.
- ML agents can also be toggled per scan request via scan `options` in the API or frontend form.
- If `ML_SERVICE_URL` is configured and reachable, ML scoring is delegated to the external service (`/v1/score-findings`, `/v1/attack-paths`, `/v1/remediation-plan`, `/v1/false-positive-candidates`) with automatic fallback to deterministic local logic.
- Set `ML_MODEL_PATH` (compose env) to enable ONNX-backed scoring in `ml-service`; if model loading or inference fails, the service automatically uses its heuristic scorer.
- Set `ML_SCORING_MODE` to control inference rollout safety: `blend` (default), `shadow` (serve deterministic output and log model deltas), or `heuristic` (force deterministic only).
- Use `ml-service/app/training_pipeline.py` to snapshot `/api/ml/engagements`, enforce quality/privacy gates, train and evaluate a candidate ONNX model, and update model registry/promotion artifacts.
- Scheduled retraining scaffold is provided in `.github/workflows/ml-training.yml` (expects `TRAINING_API_BASE` and optional `TRAINING_API_KEY` secrets).
- If `KNOWLEDGE_SERVICE_URL` is configured and reachable, the backend retrieves curated PortSwigger/OWASP/CWE context with source URLs and includes that context in AI summaries, next actions, and generated reports.
- The seed `security-knowledge` corpus stores short manually-authored notes plus citations rather than mirrored third-party article bodies; confirm licensing before importing additional content.
- Wordlist agent discovers endpoints by HTTP status code (200-399 range) with concurrent checking (5 parallel requests by default).
- Wordlists include embedded defaults + optional external sources (SecLists, Kiterunner) with local caching.
- External wordlist sources are downloaded on-demand, cached for 24 hours, and fall back to embedded defaults if unavailable.
- Control external wordlist sources via `ENABLE_SECLISTS_WORDLISTS` and `ENABLE_KITERUNNER_WORDLISTS` environment variables (both default to true).
