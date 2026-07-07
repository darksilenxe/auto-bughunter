# DOM Invader Service (plugin)

An optional sidecar that performs client-side DOM XSS taint tracking, in the
spirit of Burp Suite's **DOM Invader** extension. This is a starter scaffold
for **your own implementation** — it ships with a small, working
source→sink taint-tracking engine so it's useful immediately, with clear
extension points documented in `app/main.py`.

This service is intentionally standalone: it does not require the rest of
auto-bughunter to run. The backend's Proxy Suite consumes it as an optional
plugin — select a captured request in **Proxy > HTTP history**, open the
**Plugins** tab, and click **Run DOM Invader** to analyze that request's URL
(`POST /api/proxy/dom-invader` on the backend, which forwards to this
service's `/v1/analyze`). It is not wired into the automated scan pipeline
(no findings are persisted to the `Finding` model), and you can still call it
directly (e.g. `curl`, your own scripts) for other workflows.

## What it does

`POST /v1/analyze` loads a target URL in headless Chromium with an injected
init script that:

1. Replaces each configured **source** (`location.hash`, `document.cookie`,
   `window.name`, etc.) with a getter that tags the real value with a unique,
   inert canary string.
2. Wraps each configured **sink** (`Element.prototype.innerHTML`,
   `document.write`, `eval`, etc.) so it inspects its argument(s) for a
   canary before delegating to the real implementation.
3. Reports every source→sink flow it observes back to Python as a finding.

## Running it

Enable the optional `dom-invader` compose profile:

```bash
docker compose --profile dom-invader up -d dom-invader-service
```

Then call it directly:

```bash
curl -s -X POST https://localhost:8097/v1/analyze \
  --cacert <(docker compose exec dom-invader-service cat /certs/server.crt) \
  -H 'Content-Type: application/json' \
  -d '{"target": "https://example.com/#/vulnerable-route"}'
```

Or set `SIDECAR_AUTH_TOKEN` and pass it as a bearer token if you want to
require a shared secret.

## Extending it into your own DOM Invader

`app/main.py` documents the extension points in detail. The short version:

- Add more entries to `SOURCES` / `SINKS`, or pass `sources`/`sinks`
  overrides in the request body to test a custom set per request.
- Add postMessage, WebSocket, IndexedDB, and DOM-clobbering specific
  source/sink pairs.
- Add a "manual testing" mode that injects canaries directly into the
  address bar (hash/search) and reloads, mirroring DOM Invader's browser
  extension workflow, instead of (or in addition to) the automated
  monkey-patching approach used here.
- Add stack-trace capture on sink hits (Chromium DevTools Protocol
  `Runtime.enable` + `console.trace`) for more precise "where did this come
  from" reporting.
- Persist findings and wire them into the auto-bughunter `Finding` model
  (see `backend/internal/model/model.go`) if you want results to show up in
  the main UI — none of that plumbing exists yet, by design, so you can
  shape it to your own workflow.

## Files

- `app/main.py` — FastAPI app, taint-tracking init script, and `/v1/analyze` / `/health` endpoints.
- `Dockerfile` — Python 3.12 + Playwright Chromium image (same pattern as `sidecars/ui-simulation-service`).
- `requirements.txt` — Python dependencies.
