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
| `.env.juiceshop.example`       | Sample `.env` tuned for the harness (`ALLOWED_TARGETS=juice-shop`, optional integrations off, OAST enabled in-cluster). |
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
  reachable on. `ALLOWED_TARGETS=juice-shop` (set in the env file) is what
  authorizes the host.
- `programScopeProfile.includeHosts`: `["juice-shop"]` so runtime endpoint
  expansion stays inside the container.
- `authProfile`: a benign custom header + UA. The platform refuses scan
  creation without an `authProfile`; no real credentials are required for a
  black-box pass at Juice Shop.
- `options.crawlMaxPages: 25` to give the headless crawler some breadth.
- External integrations (Nuclei / ZAP / FFUF / Gobuster / SecLists, etc.)
  are disabled in the env file so the harness runs fully offline. Flip the
  corresponding `ENABLE_*` flags in `.env` if you want to exercise them.

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
| `TARGET_URL`    | `http://juice-shop:3000`             | Must match an entry in `ALLOWED_TARGETS` |
| `POLL_TIMEOUT`  | `1200`                               | Max seconds to wait for the job to finish |
| `POLL_INTERVAL` | `10`                                 | Seconds between status polls |
| `OUTPUT_DIR`    | `testing/juice-shop/out`             | Where artifacts are written |
