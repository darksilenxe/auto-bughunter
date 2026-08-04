# h2c_smuggling — SKILL File

- **Agent**: `h2c_smuggling` (scanner probe, not a registered multi-agent)
- **Layer**: probing
- **Status**: pilot

## 1) Purpose

Detect HTTP/2 cleartext (h2c) upgrade-smuggling vulnerabilities on scanned targets.
An h2c smuggling attack exploits front-end proxies that blindly forward `Upgrade: h2c`
requests to back-end origins, allowing an attacker to send HTTP/2 requests over the
cleartext channel that bypass the proxy's security controls (WAF, auth, rate-limiting).

## 2) Owned decisions

- Whether the target accepts an `Upgrade: h2c` HTTP/1.1 request (101 response or echoed header).
- Whether an HTTP/2 cleartext connection can carry smuggled requests that return different
  status codes or protocol versions compared to the HTTP/1.1 baseline.
- Severity classification: `critical` for confirmed smuggling anomaly, `high` for h2c
  upgrade accepted, `medium` for misconfigured h2c echo.

## 3) Required inputs

- `RunInput.Target` — the base URL of the scan target.
- `RunInput.Scope` — used for `scope.IsURLInScope` pre-flight; probe exits immediately
  for out-of-scope URLs.
- `H2CSMUGGLER_SERVICE_URL` environment variable (defaults to `https://h2csmuggler-service:8098`).
- `SIDECAR_AUTH_TOKEN` — shared secret for the sidecar.

## 4) Expected outputs

- Zero or more `model.Finding` with `Category="h2c-smuggling"` and one of:
  - `ID="h2c-smuggling-h2c-upgrade-accepted"` — `Severity=High`
  - `ID="h2c-smuggling-h2c-upgrade-echoed"` — `Severity=Medium`
  - `ID="h2c-smuggling-h2c-smuggling-anomaly"` — `Severity=Critical`
- `EvidenceFields` include: `validationType`, `findingType`, `method`, `url`,
  `oracleName=h2c_smuggling_probe`, `oracleVersion=v1`, plus raw evidence keys from
  the sidecar prefixed with `evidence.*`.
- `CWE=CWE-444`, `OWASPCategory=A02:2021`.
- Findings pass through `SubmitVerifiedFinding` with signal `EvidenceSinkObserved`.

## 5) Hard constraints

- **Scope gate**: must call `scope.IsURLInScope(target, scope)` and return nil for
  out-of-scope targets.
- **No destructive gate needed**: the probe only sends crafted HTTP headers and
  HTTP/2 requests; it does not modify server state, exfiltrate data, or execute code.
- **Sidecar availability**: if `IsAvailable` returns false the probe exits silently
  (returns nil) to keep scan results clean when the optional sidecar is not running.
- **SSRF guard**: the sidecar enforces its own SSRF blocklist; the backend additionally
  validates via `secureurl` before any outbound call.

## 6) Escalation / handoff

- If `h2c-smuggling-anomaly` is emitted, `exploit_chain` and `attack_path` agents
  should be notified; they can correlate the smuggled-path findings with access-control
  and authentication bypass findings.
- If the sidecar is unavailable, escalate to the `dynamic_command` agent to attempt
  h2csmuggler in exec mode.

## 7) Non-goals (must not do)

- Must not attempt to exploit the smuggling channel to exfiltrate real data or
  interact with back-end internal services beyond the configured smuggle paths.
- Must not run against targets that are not in `RunInput.Scope`.
- Must not be gated by `AllowDestructiveChecks` (probe is intentionally passive).
