# Auto Bughunter (Authorized Security Testing)

[![E2E - Juice Shop Harness](https://github.com/darksilenxe/auto-bughunter/actions/workflows/e2e-juice-shop.yml/badge.svg)](https://github.com/darksilenxe/auto-bughunter/actions/workflows/e2e-juice-shop.yml)
[![QA - Container Builds](https://github.com/darksilenxe/auto-bughunter/actions/workflows/qa-container-builds.yml/badge.svg)](https://github.com/darksilenxe/auto-bughunter/actions/workflows/qa-container-builds.yml)

A Dockerized starter platform for **authorized** web application security assessments.

## Important Use Policy

This project is designed for defensive testing on systems you own or are explicitly authorized to test.
Do not scan third-party systems without written permission.

## Stack

- Backend: Go API (`net/http`) with modular scanners
- Frontend: React + Vite (JavaScript)
- Headless browser checks: `chromedp` against a `chromium` sidecar over the DevTools protocol
- Containerization: Docker + Docker Compose, with heavy security tools split into per-tool sidecars (see [Architecture](#architecture))
- AI summary: OpenAI-compatible Chat Completions API

## Features

- Asynchronous scan jobs with multi-agent orchestration
- PostgreSQL-backed scan persistence
- Target allowlist enforcement (`ALLOWED_TARGETS`)
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
```

4. Open:

- Frontend: http://localhost:3000
- Backend health: http://localhost:8080/api/health

## Architecture

The backend container is intentionally slim — it ships only the Go server
binary plus the Docker CLI. Each heavy security dependency runs in its own
Docker Compose sidecar:

| Sidecar service    | Image                              | What the backend uses it for                                                            |
| ------------------ | ---------------------------------- | --------------------------------------------------------------------------------------- |
| `zap`              | `zaproxy/zap-stable:2.17.0`        | OWASP ZAP daemon + `zap-baseline.py` passive scan                                       |
| `nuclei`           | `projectdiscovery/nuclei:v3.8.0`   | Nuclei templated vulnerability scanning                                                 |
| `chromium`         | `chromedp/headless-shell:latest`   | Headless browser crawl/screenshot via DevTools (9222)                                   |
| `projectdiscovery` | local build (see `sidecars/`)      | Shared suite: `subfinder` v2.13.0, `httpx` v1.9.0, `naabu` v2.5.0, `dnsx` v1.2.3, `shuffledns` v1.2.1, `katana` v1.5.0, `tlsx` v1.2.2, `cdncheck` v1.2.31, `asnmap` v1.1.1 |
| `ffuf`             | `secsi/ffuf:2.1.0`                 | Web content fuzzing (consumes wordlist via the `shared_tmp` volume; also has read-only `/wordlists` from the kiterunner sidecar) |
| `gobuster`         | `ghcr.io/oj/gobuster`              | Directory brute-forcing (consumes wordlist via the `shared_tmp` volume; also has read-only `/wordlists` from the kiterunner sidecar) |
| `kiterunner`       | local build (see `sidecars/`)      | Assetnote `kr` API content discovery — pre-downloads every wordlist from `wordlists.assetnote.io` into the shared `assetnote_wordlists` volume on first start |
| `tool-updater`     | local build (see `sidecars/`)      | One-shot service that runs on every `docker compose up`: refreshes the `nuclei_templates` volume and queries GitHub Releases for every pinned tool, writing a JSON report consumed by `GET /api/tools/updates`. Re-run on demand via `docker compose run --rm tool-updater` |
| `sqlmap`           | `parrotsec/sqlmap`                 | SQL injection probing — keeps Python out of the backend image                           |
| `nikto`            | `ghcr.io/sullo/nikto`              | Web server scanner — keeps Perl out of the backend image                                |
| `wpscan`           | `wpscanteam/wpscan`                | WordPress scanner — keeps Ruby out of the backend image                                 |
| `agents`           | local build (see `agents/`)        | Autonomous agent learner (HTTP, port 8091)                                              |
| `ml-service`       | local build (see `ml-service/`)    | ML triage / classifier service (HTTP, port 8090)                                        |

The backend container is the **single orchestrator** of the stack: it is
the only service that holds the docker socket bind-mount, the only
service that issues `docker compose exec` into the CLI sidecars, and the
only service that issues HTTP calls to `agents` / `ml-service`. No
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

Because the shims call `docker compose exec`, the backend container has
`/var/run/docker.sock` bind-mounted. **This is effectively
root-equivalent on the host** — fine for self-hosted single-tenant
scanner usage, but not appropriate for multi-tenant deployments.

To opt out (e.g. when running the backend binary outside Docker
Compose), set `SIDECAR_EXEC_DISABLE=1`. The Go scanner will then report
the standard `<tool>-binary-missing` finding for any integration that
was enabled but cannot find its tool on `$PATH`, and the rest of the
scan will run unaffected.

## API

### `POST /api/scan`

Body:

```json
{
  "target": "https://example.com",
  "idempotencyKey": "scan-example-2026-04-09T14:00",
  "authProfile": {
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
    "useZapBaselineIntegration": false
  }
}
```

### `GET /api/scan/{id}`

Returns job state and findings, including per-agent telemetry (`agentRuns`), structured decision data (`dashboard`, `nextActions`), ML recommendations (`modelRecommendations`), asset relationships (`assetLinks`), and an automated penetration test report (`automatedReport`) with findings/severities/how-found/commands-used.

### `GET /api/ml/engagements?limit=100`

Returns a sanitized, pseudonymized engagement dataset built from completed scans and related telemetry for offline/shadow ML training and evaluation.

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

### `GET /api/automation/report`

Returns an executive automation report with scan trends, feedback quality metrics, and open automated ticket counts.

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
| `GET /api/report/{scanId}/finding/{findingId}?format=md\|pdf\|json` | Single bug-bounty submission for one finding. Defaults to Markdown. |
| `GET /api/report/{scanId}/bugbounty.zip` | Zip bundle containing one Markdown submission per finding plus a top-level `INDEX.md`. |

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

## Notes

- If `ALLOWED_TARGETS` is empty, scans are rejected.
- `authProfile` (headers/cookies/basic auth) is required for scan creation.
- If AI environment variables are missing or provider calls fail, the backend uses an offline local AI reasoner that ranks findings and proposes remediation steps.
- For OpenAI default (`https://api.openai.com/v1`), set `AI_API_KEY`; for local OpenAI-compatible containers (for example Ollama), API key can be blank.
- ML dataset generation strips/masks sensitive values (tokens/cookies/password-like data) and pseudonymizes URL/host identifiers before export.
- Job records are stored in PostgreSQL table `scans`.
- Per-scan asset inventory is stored in `scan_assets` and run events are stored in `scan_events`.
- Model recommendation artifacts are persisted in `scans.model_recommendations`.
- Finding records include confidence, source attribution, structured evidence fields, drift status, business tags, and exploitability metadata.
- Scan scope supports host wildcard patterns (`*.example.com`) and out-of-scope path prefixes.
- Scan creation and scanner execution enforce per-scan scope (target, integration expansion, and wordlist probes).
- Proxy replay supports optional per-request scope validation via `scope` on `POST /api/proxy/replay`.
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
- Wordlist agent discovers endpoints by HTTP status code (200-399 range) with concurrent checking (5 parallel requests by default).
- Wordlists include embedded defaults + optional external sources (SecLists, Kiterunner) with local caching.
- External wordlist sources are downloaded on-demand, cached for 24 hours, and fall back to embedded defaults if unavailable.
- Control external wordlist sources via `ENABLE_SECLISTS_WORDLISTS` and `ENABLE_KITERUNNER_WORDLISTS` environment variables (both default to true).
