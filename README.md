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
- Engagement-learning ML layer:
  - Tool-selection recommendations based on historical usefulness
  - Finding prioritization scores for triage ordering
  - Copilot-style suggested next actions learned from prior engagements
  - Sanitized ML training dataset export for offline/shadow model workflows

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

4. Open:

- Frontend: http://localhost:3000
- Backend health: http://localhost:8080/api/health

## API

### `POST /api/scan`

Body:

```json
{
  "target": "https://example.com",
  "authProfile": {
    "headers": {"Authorization": "Bearer ..."},
    "cookies": {"sessionid": "..."},
    "userAgent": "Mozilla/5.0",
    "basicAuthUsername": "scanner",
    "basicAuthPassword": "secret"
  },
  "options": {
    "useNucleiIntegration": false,
    "useZapBaselineIntegration": false,
    "useShuffleDnsIntegration": false,
    "useCertificateTransparencyIntegration": false,
    "useAmassIntegration": false,
    "useFfufIntegration": false,
    "useGobusterIntegration": false,
    "rescanIntervalMinutes": 0
  },
  "scope": {
    "includeHosts": ["example.com", "*.example.com"],
    "excludeHosts": ["admin.example.com"],
    "excludePaths": ["/logout", "/internal"],
    "programRules": ["No destructive testing"]
  }
}
```

### `GET /api/scan/{id}`

Returns job state and findings, including per-agent telemetry (`agentRuns`), structured decision data (`dashboard`, `nextActions`), ML recommendations (`modelRecommendations`), asset relationships (`assetLinks`), and an automated penetration test report (`automatedReport`) with findings/severities/how-found/commands-used.

### `GET /api/ml/engagements?limit=100`

Returns a sanitized, pseudonymized engagement dataset built from completed scans and related telemetry for offline/shadow ML training and evaluation.

## Notes

- If `ALLOWED_TARGETS` is empty, scans are rejected.
- `authProfile` (headers/cookies/basic auth) is required for scan creation.
- If AI environment variables are missing or provider calls fail, the backend uses an offline local AI reasoner that ranks findings and proposes remediation steps.
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
- ShuffleDNS and Certificate Transparency discovery are available as optional integrations behind `ENABLE_SHUFFLEDNS_INTEGRATION` and `ENABLE_CERTIFICATE_TRANSPARENCY_INTEGRATION`.
- Native Go Amass discovery is available behind `ENABLE_AMASS_INTEGRATION`.
- FFUF and Gobuster directory-discovery integrations are available behind `ENABLE_FFUF_INTEGRATION` and `ENABLE_GOBUSTER_INTEGRATION`.
- Destructive/high-impact checks are disabled by default; set `ALLOW_DESTRUCTIVE_CHECKS=true` only for explicitly authorized programs.
- Auth secrets are used only at execution time; persisted job data stores auth metadata summary only.
- Scans execute agents in sequence: reconnaissance → scanning → wordlist → analysis → reporting. Each agent enriches the findings pipeline.
- All agents are enabled by default; disable via code configuration if desired.
- Wordlist agent discovers endpoints by HTTP status code (200-399 range) with concurrent checking (5 parallel requests by default).
- Wordlists include embedded defaults + optional external sources (SecLists, Kiterunner) with local caching.
- External wordlist sources are downloaded on-demand, cached for 24 hours, and fall back to embedded defaults if unavailable.
- Control external wordlist sources via `ENABLE_SECLISTS_WORDLISTS` and `ENABLE_KITERUNNER_WORDLISTS` environment variables (both default to true).
