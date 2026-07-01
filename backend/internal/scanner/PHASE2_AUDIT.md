# Phase 2 audit: surface-discovery / false-negative status per probe

This document tracks the per-probe rollout of the four Phase 2 controls
introduced in the shared modules:

| Control | Module / API |
| --- | --- |
| **inv** — consumes `SurfaceInventory` for candidate endpoints | `surface_inventory.go` (`SurfaceInventory`, `NormalizeSurfaceKey`) |
| **param** — consumes miner-surfaced params via `ScanSession` | `param_discovery.go` (`DiscoverHiddenParams`) + `session.go` (`AllDiscoveredParams`, `DiscoveredParamsFor`) |
| **rec** — records probed keys for gap detection | `surface_gap_detector.go` (`RecordProbedKey`) |
| **gap** — walks unprobed high-ROI candidates | `hidden_endpoint_probe.go` (`SelectHighROIGaps`, `GapReQueueURLs`) |

Every scan builds a per-session `SurfaceInventory` in `scanner.Run`
(union of the crawl root, extracted runtime endpoints, headless XHR
endpoints, and Phase 2 hidden-parameter miner output). At the end of the
scan `DetectSurfaceGaps` compares inventory keys against
`RecordProbedKey` calls and updates process-wide
`SurfaceCoverageMetrics`, which `handleAutomationMetrics` surfaces under
`AutomationMetrics.Extra` (`surfaceTotal`, `surfaceProbed`,
`surfaceCoverageRatio`, `surfaceGapUnprobed`, `surfaceGapParamMissing`,
`surfaceGapMethodMissing`, `paramDiscoveryCandidates`,
`paramDiscoveryConfirmed`).

## Legend

- ✅ Applied.
- ➖ Not applicable (e.g. header-only probe has no per-parameter surface).
- ⚠️ **TODO** — must be added in a follow-up PR.

## Audit table

Snapshot generated 2026-07-01.

| Probe file | inv | param | rec | gap | Notes |
| --- | :---: | :---: | :---: | :---: | --- |
| `active_cors.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Header-only; record probed keys so origin coverage shows up. |
| `active_graphql_introspection.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Introspection query is per-endpoint; record `POST /graphql` key. |
| `active_ldap_injection.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Merge miner params into LDAP payload matrix. |
| `active_nosqli.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Merge miner params before NoSQL operator payloads. |
| `active_open_redirect.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `next=`, `redirect=`, `url=` style params. |
| `active_path_traversal.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Consume miner file-style params (`file`, `path`, `template`). |
| `active_prompt_injection.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner params for JSON LLM APIs. |
| `active_prototype_pollution.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Query-string miner is the primary source of `__proto__` sinks. |
| `active_sqli.go` | ✅ | ✅ | ✅ | ⚠️ | Migrated in this PR as the reference template (see `sqliDynamicParams`, `sqliMergedProbeParams`, `RecordProbedKey`). |
| `active_ssti.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Merge miner params for template-engine reflections. |
| `active_xpath_injection.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Merge miner params for XPath error surfaces. |
| `active_xss.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner params before XSS payload matrix. |
| `active_xxe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Endpoint-shaped; record probed key only. |
| `browser_storage_probe.go` | ➖ | ➖ | ➖ | ➖ | Browser-side observation. |
| `clickjacking_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Record probed key so framing coverage shows up. |
| `cloud_storage_probe.go` | ➖ | ➖ | ➖ | ➖ | Bucket enumeration, not URL-surface. |
| `command_injection_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner params for OS-command sinks (`host`, `ip`, `cmd`). |
| `cross_domain_policy_probe.go` | ➖ | ➖ | ➖ | ➖ | Fixed-path `crossdomain.xml`. |
| `csrf_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Record probed key for the state-changing endpoint set. |
| `dangling_markup.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Phase 1 reference; Phase 3 reference is the priority here. |
| `deserialization_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner params for `session=`, `token=`, `data=` style sinks. |
| `dns_san_probe.go` | ➖ | ➖ | ➖ | ➖ | Certificate metadata; no HTTP surface. |
| `dom_xss_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Fragment sinks; record probed key. |
| `file_upload_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces upload-field names. |
| `formula_injection.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Phase 1 reference; Phase 3 reference is the priority here. |
| `http_methods_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Explicitly emits `method_not_tested` signal via gap detector. |
| `jwt_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Header-based; record probed key. |
| `jwt_advanced_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Header-based; record probed key. |
| `login_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces alternate credential fields. |
| `magic_link_invite_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `token=`, `code=`, `invite=` params. |
| `mfa_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `otp=`, `code=`. |
| `oauth_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `redirect_uri=`, `state=`, `scope=`. |
| `oauth_session_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Cookie/session-focused; record probed key. |
| `password_reset_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `token=`, `email=`. |
| `postmessage_probe.go` | ➖ | ➖ | ➖ | ➖ | Browser-side observation. |
| `reverse_tabnabbing_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | HTML-only, record probed key. |
| `saml_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `SAMLResponse=`, `RelayState=`. |
| `security_headers_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Header-only; record probed key. |
| `session_lifecycle_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Cookie-focused; record probed key. |
| `smtp_injection_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `to=`, `subject=`, `body=`. |
| `ssi_injection_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner params for SSI directives. |
| `tls_config_probe.go` | ➖ | ➖ | ➖ | ➖ | Transport-level. |
| `ui_simulation_probe.go` | ➖ | ➖ | ➖ | ➖ | Browser-only. |
| `verbose_error_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner params to increase error-surface hits. |
| `websocket_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Upgrade key; record probed key. |
| `xssi_jsonp_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Miner surfaces `callback=`, `jsonp=`. |

## Reference migration

`active_sqli.go` is the Phase 2 reference. Migration pattern:

1. Before the probe loop, call
   `dynamicParams := sqliDynamicParams(input.Session)` to pull all
   miner-surfaced parameter names for this scan.
2. Inside the per-endpoint loop, call
   `probeParams := sqliMergedProbeParams(dynamicParams, endpoint)` to
   union miner params in front of the built-in wordlist (deduped, miner
   params first so they fit inside probe budgets).
3. Immediately after every HTTP send, call
   `RecordProbedKey(http.MethodGet, probeURL, paramName)` so the
   end-of-scan gap detector can distinguish `not_probed` from
   `param_not_fuzzed`.

Follow the same three steps in each probe row still marked ⚠️. Header /
cookie / transport probes only need step 3.

## Appendix — audit one-liner

```sh
grep -L 'sqliDynamicParams\|DiscoveredParamsFor\|AllDiscoveredParams\|RecordProbedKey' \
  backend/internal/scanner/*_probe.go backend/internal/scanner/active_*.go
```
