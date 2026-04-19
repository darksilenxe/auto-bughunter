# Juice Shop Test Harness

End-to-end testing environment that brings up the full Auto Bughunter stack
together with an instance of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
then runs an authorized scan and saves the resulting findings + report.

This is the recommended way to validate that the platform's scanning,
orchestration, and reporting pipeline is working before pointing it at any
real engagement target.

## Use policy

Juice Shop is a deliberately vulnerable application maintained by OWASP.
Running this harness against the bundled Juice Shop container is an
**authorized self-test** — you own the target. Do **not** repurpose this
harness against any host you are not explicitly authorized to test.

## Prerequisites

- Docker + Docker Compose v2
- `curl` and `jq` on the host running `scan.sh`
- A few GB of free RAM (the stack ships an Ollama model and Postgres)

## Layout

| File | Purpose |
|------|---------|
| `docker-compose.juiceshop.yml` | Compose overlay that adds a `juice-shop` service and makes the backend wait for it to be healthy. |
| `.env.juiceshop.example`       | Sample `.env` tuned for the harness (optional integrations off, OAST enabled in-cluster). |
| `scan.sh`                      | Submits a scan against `http://juice-shop:3000`, polls until completion, summarizes findings and downloads the Markdown pen-test report. |

## Quick start

From the repo root:

```bash
# 1. Drop the harness env in place
cp testing/juice-shop/.env.juiceshop.example .env

# 2. Boot the full stack + Juice Shop
docker compose \
  -f docker-compose.yml \
  -f testing/juice-shop/docker-compose.juiceshop.yml \
  up --build -d

# 3. Run the scan and collect artifacts
./testing/juice-shop/scan.sh
```

While the scan is running you can also browse:

- Auto Bughunter UI:  <http://localhost:3000>
- Backend health:     <http://localhost:8080/api/health>
- Juice Shop:         <http://localhost:3030>

Artifacts are written to `testing/juice-shop/out/`:

- `scan-create.json` — original `POST /api/scan` response
- `scan-<id>.json`   — final job record (status, findings, dashboard, etc.)
- `report-<id>.md`   — Markdown pen-test report

## How the scan request is built

`scan.sh` sends a single `POST /api/scan` request. The important fields:

- `target`: `http://juice-shop:3000` — the in-cluster hostname Juice Shop is
  reachable on.
- `programScopeProfile.includeHosts`: `["juice-shop"]` so runtime endpoint
  expansion stays inside the container.
- `authProfile`: a benign custom header + UA. The platform refuses scan
  creation without an `authProfile`; no real credentials are required for a
  black-box pass at Juice Shop.
- `options.crawlMaxPages: 25` to give the headless crawler some breadth.
- External integrations (Nuclei / ZAP / FFUF / Gobuster / SecLists, etc.)
  are disabled in the env file so the harness runs fully offline. Flip the
  corresponding `ENABLE_*` flags in `.env` if you want to exercise them.

## Running in CI

This harness also runs unattended on GitHub Actions via
[`.github/workflows/e2e-juice-shop.yml`](../../.github/workflows/e2e-juice-shop.yml).
That workflow brings up the same compose stack (minus the heavy bits — see
below), runs `scan.sh`, asserts the job completed and produced at least one
finding, and uploads `testing/juice-shop/out/` plus `docker compose logs` as
build artifacts.

Triggers:

- `workflow_dispatch` (manual; lets you tweak crawl budget / poll timeout / minimum findings)
- Nightly `schedule` at 04:17 UTC
- `pull_request`, but **only** when the PR carries the `run-e2e` label — the
  job is too heavy to gate every PR on by default.

To slim the stack for the runner the workflow:

- Starts only `db`, `ml-service`, `agents`, `backend`, and `juice-shop`
  (no frontend — the harness drives the API directly).
- Skips Ollama entirely. The `ollama` and `ollama-init` services in the
  root `docker-compose.yml` live under the `ollama` compose profile, so they
  do not start unless you explicitly pass `--profile ollama`. The CI step
  also blanks out `AI_API_BASE` / `AI_API_KEY` / `AI_MODEL` in `.env` so the
  backend doesn't try to call a model that isn't running.

Locally, if you want the AI summaries you can opt in with:

```bash
docker compose --profile ollama \
  -f docker-compose.yml \
  -f testing/juice-shop/docker-compose.juiceshop.yml \
  up --build
```

## Tear-down

```bash
docker compose \
  -f docker-compose.yml \
  -f testing/juice-shop/docker-compose.juiceshop.yml \
  down -v
```

## Tuning

`scan.sh` accepts a few env overrides:

| Variable        | Default                              | Notes |
|-----------------|--------------------------------------|-------|
| `API_BASE`      | `http://localhost:8080`              | Backend API base URL |
| `TARGET_URL`    | `http://juice-shop:3000`             | Target URL for the scan |
| `POLL_TIMEOUT`  | `1200`                               | Max seconds to wait for the job to finish |
| `POLL_INTERVAL` | `10`                                 | Seconds between status polls |
| `OUTPUT_DIR`    | `testing/juice-shop/out`             | Where artifacts are written |
| `CRAWL_MAX_PAGES` | `25`                               | Crawl budget passed to the scanner (CI lowers this for speed) |
