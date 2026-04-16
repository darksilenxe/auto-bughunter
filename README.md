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
- Optional external ML inference service: FastAPI + ONNX Runtime

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
- Optional AI-generated executive summary for findings
- Offline AI reasoner (local analysis when no API available)
- Deterministic ML scoring service for explainable prioritization (no external model dependency)
- Optional external ML microservice integration (score, attack paths, remediation plan, false-positive candidates)
- Optional ONNX model-backed scoring in the ML service via `ML_MODEL_PATH`

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
    "useMlTriageAgent": true,
    "useAttackPathAgent": true,
    "useFalsePositiveReviewAgent": true,
    "useRemediationPlannerAgent": true
  }
}
```

### `GET /api/scan/{id}`

Returns job state and findings.

## Notes

- If `ALLOWED_TARGETS` is empty, scans are rejected.
- If AI environment variables are missing or provider calls fail, the backend uses an offline local AI reasoner that ranks findings and proposes remediation steps.
- Job records are stored in PostgreSQL table `scans`.
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
