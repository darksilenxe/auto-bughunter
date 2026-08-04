# h2csmuggler Service

An optional sidecar that probes HTTP targets for **HTTP/2 cleartext (h2c)
upgrade smuggling** vulnerabilities, inspired by the
[h2csmuggler](https://github.com/assetnote/h2csmuggler) tool by Assetnote.

The backend scanner's `h2c_smuggling_probe` consumes this service
automatically when the `h2csmuggler` compose profile is enabled. It is not
in the default scan pipeline — start it explicitly if you want h2c smuggling
coverage.

## How it works

1. `POST /v1/scan` accepts a target URL.
2. The service sends an HTTP/1.1 request with `Upgrade: h2c` and
   `Connection: Upgrade, HTTP2-Settings` headers to discover whether the
   server (or an intermediary reverse proxy) transparently upgrades to HTTP/2
   over cleartext.
3. If an h2c upgrade is accepted (101 response or echoed `Upgrade: h2c`
   header) the service attempts to send HTTP/2 requests over the cleartext
   channel targeting paths that might bypass proxy / WAF inspection (e.g.
   `/../admin`, `/../api`).
4. Differences in status codes, response protocols, or h2c acceptance are
   reported as structured findings.

### Finding types

| `type` | Meaning | Default severity |
|---|---|---|
| `h2c-upgrade-accepted` | Server responded with `101 Switching Protocols` | High |
| `h2c-upgrade-echoed` | Server echoed `Upgrade: h2c` without issuing 101 | Medium |
| `h2c-smuggling-anomaly` | Smuggled HTTP/2 path returned different status or protocol | Critical |

## Running it

Enable the optional `h2csmuggler` compose profile:

```bash
docker compose --profile h2csmuggler up -d h2csmuggler-service
```

Call the health endpoint to verify it started:

```bash
curl -s --cacert <(docker compose exec h2csmuggler-service cat /certs/server.crt) \
  https://localhost:8098/health
```

Run a scan manually:

```bash
curl -s -X POST https://localhost:8098/v1/scan \
  --cacert <(docker compose exec h2csmuggler-service cat /certs/server.crt) \
  -H "Authorization: ******" \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://target.example.com", "timeout": 15}'
```

The scanner wires this automatically when the service URL is reachable
(`H2CSMUGGLER_SERVICE_URL` defaults to `https://h2csmuggler-service:8098`).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `SIDECAR_AUTH_TOKEN` | *(required)* | Shared bearer token for mTLS-less callers. Must be set; the service refuses to start without it. |
| `H2CSMUGGLER_LOG_LEVEL` | `INFO` | Python `logging` level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

Set `H2CSMUGGLER_SERVICE_URL` in the backend's environment to override the
default service URL (useful for local development outside Docker Compose).

## Request / response schema

### `POST /v1/scan`

**Request body:**

```json
{
  "url": "https://target.example.com",
  "smuggle_paths": ["/../admin", "/../api"],
  "timeout": 15
}
```

`smuggle_paths` is optional; defaults to a built-in list of high-interest
paths (`/`, `/../admin`, `/../api`, `/../internal`, etc.).

**Response body:**

```json
{
  "url": "https://target.example.com",
  "h2c_upgrade_accepted": true,
  "smuggle_attempted": true,
  "findings": [
    {
      "type": "h2c-smuggling-anomaly",
      "description": "One or more smuggled HTTP/2 requests returned a different status code…",
      "evidence": {
        "url": "https://target.example.com",
        "baseline_status": 403,
        "anomalous_paths": [{"path": "/../admin", "status": 200, "protocol": "HTTP/2"}],
        "all_results": [...]
      }
    }
  ],
  "error": null
}
```

### `GET /health`

Returns `{"status": "ok", "service": "h2csmuggler"}` with HTTP 200. No
authentication required (exempt from bearer-token check).

## Security notes

- **SSRF guard:** the service resolves the target hostname and rejects
  requests that point at RFC 1918, loopback, link-local, or other private
  addresses to prevent SSRF abuse.
- **mTLS:** the service uses the shared `sidecar_certs` volume for TLS; all
  production traffic between the backend and this sidecar is TLS-encrypted.
- **Auth token:** every `POST /v1/scan` request must carry
  `Authorization: ****** The service exits at startup
  if the token is not configured.
- The probe is **always-on** (no `ALLOW_DESTRUCTIVE_CHECKS` gate required)
  because it only sends HTTP/1.1 upgrade and plain HTTP/2 GET requests — it
  does not modify server state.

## Files

- `app/main.py` — FastAPI app, SSRF guard, h2c upgrade probe, smuggling probe,
  `/v1/scan`, and `/health` endpoints.
- `Dockerfile` — Python 3.12 slim image.
- `requirements.txt` — Python dependencies (`fastapi`, `uvicorn`, `httpx[http2]`,
  `h2`, `hpack`, `hyperframe`, `pydantic`).
