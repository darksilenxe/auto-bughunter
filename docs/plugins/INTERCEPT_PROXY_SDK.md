# Intercept Proxy Plugin SDK (Wave 2)

This SDK contract defines how third-party intercept-proxy plugins integrate with Auto Bughunter.

## Contract version

- **Current host/plugin API version:** `v1`
- Manifest `apiVersion` **must** equal `v1`.

## Manifest schema

Plugins must provide a manifest JSON document with:

```json
{
  "name": "my-plugin",
  "version": "1.0.0",
  "apiVersion": "v1",
  "endpoint": "http://my-plugin:9000",
  "capabilities": ["request", "response", "passive"],
  "hooks": ["request.mutate", "response.observe", "passive.finding"]
}
```

## Required fields

- `name` (string)
- `version` (string)
- `apiVersion` (string, currently `v1`)
- `endpoint` (string URL reachable by backend)

## Compatibility harness expectations

The backend compatibility harness validates:

1. Required manifest fields exist.
2. `apiVersion` equals `v1`.
3. Empty plugin set is accepted (baseline no-plugin regression path).

Reference implementation:

- `backend/internal/proxy/plugin_contract.go`
- `backend/internal/proxy/plugin_contract_test.go`

