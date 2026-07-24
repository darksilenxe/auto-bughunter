# AGENTS.md — Auto Bughunter

This file is the authoritative guide for AI coding agents working in this repository.
Read it before making any change.

---

## Repository Overview

Auto Bughunter is a **Dockerized, multi-agent security assessment platform** for
authorized web application vulnerability scanning.  It is **not** a generic
web crawler; every probe is gated by explicit authorization checks and a scope
allowlist.

Primary audiences: solo bug bounty hunters, small pentest teams, internal AppSec teams.

---

## Repository Layout

```
auto-bughunter/
├── backend/            Go API server (net/http) — the single orchestrator
│   ├── cmd/            CLI entry points (autobughunter, accuracy-bench, replayharness, standalone)
│   ├── internal/       All internal packages
│   │   ├── agent/      Multi-agent system (orchestrator, factory, all agents)
│   │   ├── scanner/    All security probes (~100 files)
│   │   ├── ai/         AI client (OpenAI-compatible, Anthropic, Gemini, Bedrock, Ollama)
│   │   ├── ml/         ML service client
│   │   ├── model/      Shared data types (Finding, ScanOptions, …)
│   │   ├── secureurl/  Outbound URL validator (enforces HTTPS for public hosts)
│   │   ├── scope/      Target scope enforcement
│   │   └── storage/    PostgreSQL persistence (pgvector + pgx)
│   ├── scripts/shims/  Thin shell wrappers that exec into tool sidecars
│   └── templates/      JSON/text templates (Metasploit RPC module list, etc.)
├── frontend/           React + Vite SPA (JavaScript, Node 20)
├── ml-service/         Python FastAPI ML triage service (port 8090)
├── agents/             Python autonomous agent learner sidecar (port 8091)
├── security-knowledge/ Python retrieval-only knowledge sidecar (port 8092)
├── sidecars/           Dockerfiles/configs for every external tool sidecar
│   ├── nuclei-service/ HTTP wrapper around Nuclei (USE_HTTP_TOOL_SERVICES=true)
│   ├── zap-service/    HTTP wrapper around ZAP
│   ├── kiterunner/     Assetnote kr API wordlist sidecar
│   ├── projectdiscovery/ Subfinder, httpx, naabu, dnsx, shuffledns, katana, …
│   └── …
├── docs/
│   ├── skills/         Agent SKILL responsibility files (source of truth)
│   └── openhack/       OpenHack expert prompt references
├── testing/            Replay harness fixtures and test data
├── docker-compose.yml
├── docker-compose.kali.yml
├── docker-compose.gpu.yml
└── .env.example
```

---

## Build, Test, and Lint Commands

### Backend (Go)

```bash
cd backend

# Vet
go vet ./...

# Build everything (including CLI)
go build ./...

# Run all tests
go test ./...

# Run accuracy benchmark gate
go test ./internal/accuracybench/... ./cmd/accuracy-bench/...
go build -o /tmp/accuracy-bench ./cmd/accuracy-bench
/tmp/accuracy-bench \
  -corpus ./cmd/accuracy-bench/testdata/corpus \
  -actuals ./cmd/accuracy-bench/testdata/actuals \
  -output-json /tmp/accuracy-report.json \
  -output-md /tmp/accuracy-report.md

# Replay planner regression gate
go run ./cmd/replayharness \
  -input ../testing/replay/ai-planner-history.json \
  -baseline static -candidate recorded \
  -min-candidate-match-rate 0.95 \
  -min-candidate-first-choice-rate 0.95 \
  -max-candidate-early-stops 0 \
  -require-candidate-not-worse
```

The CI workflow (`.github/workflows/qa.yml`) runs `go vet`, `go build`, `go test`,
the accuracy benchmark gate, and the replay planner gate on every PR that touches
`backend/`.

### Frontend (Node 20 / Vite)

```bash
cd frontend
npm ci
npm run build
```

### ML Service (Python)

```bash
cd ml-service
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8090
```

### Full Stack

```bash
# Standard (no local LLM)
docker compose up --build

# With Ollama local LLM
docker compose --profile ollama up --build

# Kali high-resource override
docker compose -f docker-compose.yml -f docker-compose.kali.yml up --build

# GPU-accelerated Ollama
docker compose -f docker-compose.yml -f docker-compose.gpu.yml \
  --profile ollama up --build
```

---

## Key Conventions

### Go Backend

- **Module path:** `auto-bughunter/backend` (see `backend/go.mod`)
- **Go version:** declared in `backend/go.mod` (currently `go 1.25.0`)
- **No global state outside packages** — each agent/scanner is instantiated by
  the Factory or test setup.
- **Scanner probes** live in `backend/internal/scanner/`. Each probe file has a
  matching `_test.go`. Follow the existing table-driven test pattern.
- **Agent files** live in `backend/internal/agent/`. Registration happens in
  `factory.go` — every new agent must be registered there.
- **SKILL files** (`docs/skills/pilot/`) must be updated in the same PR as any
  new agent registration or significant agent behavior change.
- **Outbound URL validation:** all configurable URLs the backend calls are
  validated by `backend/internal/secureurl`. HTTPS is required for any
  public-internet host; plain HTTP is only allowed for loopback, RFC 1918, and
  single-label Docker Compose hostnames. Do not bypass this check without a
  strong documented reason.
- **Scope enforcement:** every active probe must check `scope.IsInScope(target)`
  before firing. Do not send requests to hosts not in the allowed scan scope.
- **Safety gate:** destructive checks (SQLMap, commix, XSSMap, PoC execution)
  require `ALLOW_DESTRUCTIVE_CHECKS=true` and `EnableCVEPoCExecution` in scan
  options. Never enable them unconditionally.
- **Error handling:** use the Go idiom `if err != nil { return ..., err }`.
  Log errors at the point of origin; do not silence them.

### Frontend (React + Vite)

- Entry: `frontend/src/main.jsx` → `frontend/src/App.jsx`
- Components live in `frontend/src/components/` and `frontend/src/pages/`.
- Uses Vite for dev/build. No TypeScript — plain JavaScript.

### Python Services (ml-service, agents, security-knowledge)

- FastAPI + uvicorn.
- Keep the HTTP API contract stable — the backend calls these services; breaking
  changes require updating both sides in the same PR.
- `ml-service/API_CONTRACT.md` documents the expected request/response shapes.

### Docker Compose / Sidecars

- Each tool sidecar is isolated; no sidecar talks to another sidecar.
- The backend is the **sole orchestrator** — it holds the Docker socket mount
  and issues all HTTP calls to other services.
- Two integration modes: **HTTP mode** (`USE_HTTP_TOOL_SERVICES=true`,
  preferred — no Docker socket needed) and **exec mode** (legacy, requires
  Docker socket bind-mount).

---

## Agent System

The platform's built-in multi-agent system is implemented in
`backend/internal/agent/`. Agents are instantiated by `Factory` and scheduled
by `Orchestrator` in a plan → build → run loop.

### Registered agents (from `factory.go`)

| Agent name | File | Role |
|---|---|---|
| `reconnaissance` | `reconnaissance.go` | DNS, tech stack, endpoint discovery |
| `js_sast` | `js_sast.go` | Static analysis of JavaScript bundles |
| `scanning` | `scanning.go` | Core security probes |
| `advanced_coverage` | `advanced_coverage.go` | Extended surface coverage |
| `input_validation` | `input_validation.go` | Injection probes |
| `information_disclosure` | `information_disclosure.go` | Sensitive data leakage checks |
| `access_control` | `access_control.go` | IDOR, privilege escalation |
| `api_security` | `api_security.go` | REST/GraphQL API checks |
| `cors_redirect` | `cors_redirect.go` | CORS and open-redirect probes |
| `ssrf` | `ssrf.go` | SSRF probes (header + body, OAST-backed) |
| `auth_bypass` | `auth_bypass.go` | Authentication bypass |
| `file_upload` | `file_upload.go` | File upload abuse |
| `metasploit` | `metasploit.go` | Optional Metasploit RPC integration |
| `burp` | `burp.go` | Optional Burp Suite API integration |
| `wordlist` | `wordlist.go` | Directory/subdomain/API endpoint fuzzing |
| `ai_tool_calling` | `ai_tool_calling_agent.go` | LLM-driven tool orchestration |
| `tool_builder` | `tool_builder.go` | Dynamic command construction |
| `analysis` | `analysis.go` | Finding deduplication and severity ranking |
| `ml_triage` | `ml_ai_agents.go` | Deterministic risk scoring via ML service |
| `attack_path` | `ml_ai_agents.go` | Multi-step attack chain correlation |
| `false_positive_review` | `ml_ai_agents.go` | Confidence-based FP shortlist |
| `remediation_planner` | `ml_ai_agents.go` | Prioritized remediation sequence |
| `impact_verifier` | `impact_verifier.go` | Exploitability estimation |
| `reporting` | `reporting.go` | Executive summary generation |
| `exploit_chain` | `exploit_chain_agent.go` | Deterministic multi-step chain analysis |
| `hypothesis` | `hypothesis_agent.go` | Rule-based or LLM hypothesis generation |
| `hacktricks_techniques` | `hacktricks_agent.go` | HackTricks command template instantiation |
| `llm_chain_synthesis` | `llm_chain_synthesis_agent.go` | LLM cross-finding chain reasoning |
| `cve_reverse_engineer` | `cve_agent.go` | CVE root-cause write-up + PoC proposal |
| `openhack_expert` | `openhack_expert.go` | OpenHack expert-prompt integration |
| `openhack_triage` | `openhack_triage.go` | OpenHack finding re-triage |
| `pentest_loop` | `pentest_loop_agent.go` | Iterative pentest loop |
| `reasoning_iteration` | `reasoning_iteration_agent.go` | Iterative reasoning pass |
| `dynamic_command` | `dynamic_command.go` | Dynamic OS command execution |
| `adaptive_probe` | `adaptive_probe_agent.go` | Adaptive probe scheduling |

### Adding a new agent

1. Create `backend/internal/agent/<name>.go` and implement the `Agent` interface.
2. Register it in `factory.go` with `f.Register("<name>", func() Agent { ... })`.
3. Add (or update) the corresponding SKILL file under `docs/skills/` using the
   schema in `docs/skills/SKILL_SPEC.md`.
4. Add tests in `<name>_test.go` following the existing table-driven pattern.

---

## Environment Variables (Key Ones)

See `.env.example` for the full list.  The most relevant for development:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `BOOTSTRAP_ADMIN_API_KEY` | Admin API key (never use a known default) |
| `AI_API_BASE` / `AI_API_KEY` / `AI_MODEL` | Primary LLM provider |
| `AI_CODING_MODEL` | Orchestration planner model |
| `AI_FAST_MODEL` | Fast/cheap model for high-frequency decisions |
| `ALLOW_DESTRUCTIVE_CHECKS` | Enable SQLMap, commix, XSSMap (default: false) |
| `USE_HTTP_TOOL_SERVICES` | Use HTTP wrappers instead of Docker socket exec |
| `ALLOW_INSECURE_OUTBOUND_URLS` | Bypass HTTPS guard (escape hatch only) |
| `NEO4J_URI` | Leave empty to disable optional attack-graph persistence |
| `CHROME_REMOTE_URL` | Headless Chromium DevTools endpoint |

---

## CI Workflows

| Workflow file | Trigger | What it checks |
|---|---|---|
| `qa.yml` | PR (backend/ or frontend/), push to main | `go vet`, `go build`, `go test`, accuracy benchmark gate, replay planner gate, `npm ci`, `npm run build` |
| `qa-container-builds.yml` | Manual, scheduled | Full Docker Compose build |
| `e2e-juice-shop.yml` | Manual, scheduled | End-to-end scan against OWASP Juice Shop |
| `qa-accuracy.yml` | Manual | Accuracy benchmark run |
| `ml-training.yml` | Manual | ML training pipeline |
| `ensure-labels.yml` | PR | Label hygiene |

All PRs that touch `backend/` or `frontend/` must pass `qa.yml`.

---

## Important Files to Know

| File | Why it matters |
|---|---|
| `backend/internal/agent/factory.go` | Single registration point for all agents |
| `backend/internal/agent/orchestrator.go` | Plan→build→run loop logic |
| `backend/internal/scanner/scanner.go` | Top-level scan coordinator |
| `backend/internal/secureurl/` | Outbound URL safety validator — do not bypass |
| `backend/internal/scope/` | Scan scope enforcement |
| `backend/internal/model/` | Shared data types used across the stack |
| `docs/skills/README.md` | Agent SKILL governance rules |
| `docs/skills/SKILL_SPEC.md` | Required schema for every SKILL file |
| `backend/internal/scanner/PHASE1_AUDIT.md` | FP reduction rollout plan |
| `backend/internal/scanner/PHASE2_AUDIT.md` | FN reduction rollout plan |
| `backend/internal/scanner/PHASE3_AUDIT.md` | Typed evidence schema plan |
| `ml-service/API_CONTRACT.md` | ML service HTTP contract |
| `ROADMAP.md` | Strategic backlog and wave plan |

---

## Ethics and Scope Constraints

- This platform is for **authorized testing only**. Do not add probes that run
  against targets without scope validation.
- All scope checks flow through `backend/internal/scope`. Every new probe must
  call scope validation before firing any network request.
- Destructive probes (anything that modifies state, exfiltrates data, or executes
  code on the target) must be gated by `ScanOptions.AllowDestructiveChecks` or
  the equivalent per-feature flag.
- OAST callbacks must use the configured `OAST_POLLING_ENDPOINT` — do not
  hard-code external services.
