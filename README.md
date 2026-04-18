# Auto Bughunter (Authorized Security Testing)

A Dockerized starter platform for **authorized** web application security assessments.

## Important Use Policy

This project is designed for defensive testing on systems you own or are explicitly authorized to test.
Do not scan third-party systems without written permission.

## Stack

- Backend: Go API (`net/http`) with modular scanners
- Frontend: React + Vite (JavaScript)
- Headless browser checks: `chromedp` + Chromium
- Containerization: Docker + Docker Compose
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

### `GET /api/scan/{id}/sarif`

Returns the scan findings as a [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) document so they can be uploaded directly into GitHub code scanning, Microsoft Defender, or any other SARIF-aware sink. Severity is mapped to SARIF level (`high → error`, `medium → warning`, `low/info → note`).

### `GET /metrics`

Prometheus-style text exposition of operational counters: HTTP requests by method/status, total scans started, scans completed (by outcome), findings produced (by severity), webhook delivery success/failure, and counts of requests rejected by the rate limiter or auth middleware. This endpoint is exempt from API token authentication so Prometheus can scrape it without credentials.

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
- Set `API_TOKEN` to require a bearer token on all `/api/*` routes (except `/api/health` and `/metrics`). The token is accepted via `Authorization: Bearer <token>` or `X-API-Token: <token>`.
- Set `API_RATE_LIMIT_PER_MINUTE` to apply a per-client (per-IP, honoring `X-Forwarded-For`) rate limit on the API. Limited responses include `X-RateLimit-*` and `Retry-After` headers.
- Set `WEBHOOK_SIGNING_SECRET` to sign outbound `SCAN_WEBHOOK_URL` payloads with HMAC-SHA256. Consumers verify the `X-Auto-Bughunter-Signature` header (format: `sha256=<hex>`).
- Operational metrics are exposed in Prometheus text format on `GET /metrics` (HTTP request counts, scan totals, finding counts by severity, webhook outcomes, rate-limit/auth rejections).
- SARIF export of findings is available at `GET /api/scan/{id}/sarif` for ingestion into GitHub code scanning or other SARIF-aware tools.
- Destructive/high-impact checks are disabled by default; set `ALLOW_DESTRUCTIVE_CHECKS=true` only for explicitly authorized programs.
- Auth secrets are used only at execution time; persisted job data stores auth metadata summary only.
- Scans execute agents in sequence: reconnaissance → scanning → specialized security agents → wordlist → analysis → ML triage → attack path synthesis → false-positive review → remediation planning → reporting. Each agent enriches the findings pipeline.
- ML agents can be controlled per deployment with `ENABLE_ML_TRIAGE_AGENT`, `ENABLE_ATTACK_PATH_AGENT`, `ENABLE_FALSE_POSITIVE_REVIEW_AGENT`, and `ENABLE_REMEDIATION_PLANNER_AGENT`.
- ML agents can also be toggled per scan request via scan `options` in the API or frontend form.
- If `ML_SERVICE_URL` is configured and reachable, ML scoring is delegated to the external service (`/v1/score-findings`, `/v1/attack-paths`, `/v1/remediation-plan`, `/v1/false-positive-candidates`) with automatic fallback to deterministic local logic.
- Set `ML_MODEL_PATH` (compose env) to enable ONNX-backed scoring in `ml-service`; if model loading or inference fails, the service automatically uses its heuristic scorer.
- Wordlist agent discovers endpoints by HTTP status code (200-399 range) with concurrent checking (5 parallel requests by default).
- Wordlists include embedded defaults + optional external sources (SecLists, Kiterunner) with local caching.
- External wordlist sources are downloaded on-demand, cached for 24 hours, and fall back to embedded defaults if unavailable.
- Control external wordlist sources via `ENABLE_SECLISTS_WORDLISTS` and `ENABLE_KITERUNNER_WORDLISTS` environment variables (both default to true).
