# Sidecar TLS mesh

The backend talks to five HTTP sidecars in the docker-compose stack:

| Sidecar              | Default URL                          |
|----------------------|---------------------------------------|
| `ml-service`         | `https://ml-service:8090`             |
| `agents`             | `https://agents:8091`                 |
| `security-knowledge` | `https://security-knowledge:8092`     |
| `nuclei-service`     | `https://nuclei-service:8093`         |
| `zap-service`        | `https://zap-service:8094`            |

All five connections are TLS-encrypted inside the compose network so a
compromise of any peer container can't passively sniff finding data,
auth tokens, or scan inputs.

## How it works

A one-shot **`tls-init`** container runs at the start of every
`docker compose up`. Its
[`entrypoint.sh`](../sidecars/tls-init/entrypoint.sh) generates (or
reuses) a self-signed RSA cert valid for 10 years and writes it to the
shared `sidecar_certs` named volume:

```
/certs/server.crt   # PEM cert; also acts as its own CA root
/certs/server.key   # matching private key
```

The cert's SubjectAltName lists every sidecar service hostname plus
`localhost`/`127.0.0.1`, so:

- Each sidecar mounts the volume read-only and serves HTTPS via
  `uvicorn --ssl-keyfile /certs/server.key --ssl-certfile /certs/server.crt`.
  The compose `command:` for each sidecar wires those flags in.
- Each sidecar's healthcheck verifies against `/certs/server.crt` on
  `https://localhost:PORT/health` (the `localhost` SAN lets verify=True
  succeed).
- The backend mounts the same volume read-only at
  `/etc/auto-bughunter/sidecar-ca` and points `SIDECAR_CA_BUNDLE` at
  `server.crt`. The shared
  [`backend/internal/sidecartls`](../backend/internal/sidecartls/sidecartls.go)
  helper loads the bundle once and installs a TLS-aware
  `*http.Transport` on every sidecar client constructor in
  `ml`, `knowledge`, `agentlearner`, and `toolclient/{nuclei,zap}`.

The cert is generated **once** per volume — subsequent compose restarts
reuse the existing keypair. Delete the `sidecar_certs` volume
(`docker compose down -v`) to rotate keys.

## Out-of-scope (still plaintext)

| Path                              | Reason                                            |
|-----------------------------------|---------------------------------------------------|
| Browser → backend `:8081` proxy   | MITM proxy must terminate plaintext requests.     |
| `backend` ↔ Postgres / Neo4j      | Datastore TLS deferred (see ROADMAP).             |
| Frontend nginx                    | Public TLS belongs at the reverse-proxy / LB.     |

## Backend-outside-compose / unit tests

The sidecar TLS helper is a no-op when `SIDECAR_CA_BUNDLE` is unset, the
file is missing, or the PEM is empty. In all three cases the helper logs
a single warning and the affected `*http.Client` falls back to
`http.DefaultTransport`, so:

- Plain `http://` URLs continue to work for developers running
  `go run ./cmd/server` outside the compose stack.
- `httptest.NewServer` URLs in `*_test.go` are unaffected (they're
  `http://`, not `https://`, and never read the bundle).

The `ALLOW_INSECURE_OUTBOUND_URLS=true` escape hatch (see `.env.example`)
also still applies if you need to override the per-URL HTTPS guard.
