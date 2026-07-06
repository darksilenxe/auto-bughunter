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

`scanner.go`'s `Run` now feeds the `DetectSurfaceGaps` output straight
into `(*Service).runGapReQueuePass` (`phase2_gap_requeue.go`), which:

1. Calls `SelectHighROIGaps(gaps, gapReQueueBudget)` (budget 15) to pick
   the highest-value unprobed/under-fuzzed inventory entries.
2. Projects them to URLs via `GapReQueueURLs` and drops any URL that was
   already part of the first pass's `SeedRuntimeEndpoints` (so the pass
   is strictly additive, not duplicate work).
3. Re-invokes the migrated Batch 1/Batch 2 probes that already consume
   `input.Options.SeedRuntimeEndpoints` with the new gap URLs appended,
   so late-discovered surface (runtime-XHR endpoints, miner-surfaced
   params, etc. that only populate the inventory partway through the
   first pass) still gets fuzzed within the same scan.
4. Annotates every finding produced by the second pass with
   `(surfaced via Phase 2 gap-requeue pass)` so operators can tell it
   apart from first-pass findings in the report.

`clickjacking_probe.go` doesn't itself consume `SeedRuntimeEndpoints`
(header-only, single-URL check), so the re-queue pass fetches up to
`gapReQueueClickjackingMax` (5) of the gap URLs directly
(`gapReQueueClickjackingProbe`) and runs the existing header check
against each live response.

## Legend

- ✅ Applied.
- ➖ Not applicable (e.g. header-only probe has no per-parameter surface).
- ⚠️ **TODO** — must be added in a follow-up PR.

## Audit table

Snapshot generated 2026-07-01.

| Probe file | inv | param | rec | gap | Notes |
| --- | :---: | :---: | :---: | :---: | --- |
| `active_cors.go` | ✅ | ➖ | ✅ | ✅ | now consumes the Phase 2 gap-requeue pass (`runGapReQueuePass`), so unprobed high-ROI origins/endpoints surfaced late in the first pass get re-tried. |
| `active_graphql_introspection.go` | ✅ | ➖ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed introspection endpoints. |
| `active_ldap_injection.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_nosqli.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_open_redirect.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_path_traversal.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_prompt_injection.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_prototype_pollution.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_sqli.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_ssti.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_xpath_injection.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_xss.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `active_xxe.go` | ✅ | ➖ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `browser_storage_probe.go` | ➖ | ➖ | ➖ | ➖ | Browser-side observation. |
| `clickjacking_probe.go` | ✅ | ➖ | ✅ | ✅ | gap-requeue pass fetches up to 5 re-queued gap URLs directly (`gapReQueueClickjackingProbe`) and runs the header check on each, since this probe has no native SeedRuntimeEndpoints loop. |
| `cloud_storage_probe.go` | ➖ | ➖ | ➖ | ➖ | Bucket enumeration, not URL-surface. |
| `command_injection_probe.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `cross_domain_policy_probe.go` | ➖ | ➖ | ➖ | ➖ | Fixed-path `crossdomain.xml`. |
| `csrf_probe.go` | ✅ | ➖ | ✅ | ✅ | Consumes SurfaceInventory (POST/PUT/PATCH/DELETE) and records probed keys per (method, url). Bypass matrix covers empty-value, method-override, duplicate-token, default-token. |
| `dangling_markup.go` | ✅ | ✅ | ✅ | ✅ | now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `deserialization_probe.go` | ✅ | ➖ | ✅ | ⚠️ | Endpoint+body-shaped like `active_xxe.go` (fixed serialized-format preambles, no per-parameter fuzz matrix); `RecordProbedKey` added to the active-probe and passive-observation loops. Does not carry a `*ScanSession` today (see `RunInput`-less signature) — a future PR would need to thread `Session` through `AdvancedCoverageAgent` before `param` could apply. |
| `dns_san_probe.go` | ➖ | ➖ | ➖ | ➖ | Certificate metadata; no HTTP surface. |
| `dom_xss_probe.go` | ✅ | ➖ | ✅ | ⚠️ | Fragment sink (location.hash), no query-parameter matrix; `RecordProbedKey` added per navigated endpoint. |
| `file_upload_probe.go` | ✅ | ✅ | ✅ | ⚠️ | Migrated: miner-surfaced upload-field names are merged in front of the built-in `"file"` field via the new `buildMultipartUploadField`/`executeUploadAttemptField` helpers; `RecordProbedKey` records `(POST, url, fieldName)`. |
| `formula_injection.go` | ✅ | ✅ | ✅ | ⚠️ | Migrated: miner params merged in front of `formulaProbeParams`; `RecordProbedKey` added. |
| `http_methods_probe.go` | ✅ | ➖ | ✅ | ⚠️ | `RecordProbedKey` added to `probeOptionsMethod` (OPTIONS), `probeTraceMethod` (TRACE), and `probeVerbOverride` (baseline GET + tunnelled DELETE), so the gap detector can see per-method coverage. |
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

`phase2_probe_params.go` (`phase2DynamicParams`, `phase2ProbeParams`)
generalises steps 1-2 into a shared helper so subsequently migrated
probes (`active_ldap_injection.go`, `active_nosqli.go`,
`active_open_redirect.go`, `active_path_traversal.go`,
`active_prompt_injection.go`, `active_ssti.go`,
`active_xpath_injection.go`, `active_xss.go`, `command_injection_probe.go`,
`dangling_markup.go`, `formula_injection.go`) do not each re-derive their
own `*DynamicParams`/`*MergedProbeParams` pair. `active_prototype_pollution.go`
uses a variant, `prototypePollutionProbeKeys`, that nests each
miner-discovered name as a `<param>[__proto__][polluted]` gadget key
instead of a flat parameter merge. `file_upload_probe.go` uses the same
helper but merges miner-surfaced names into the multipart *field name*
list (`buildMultipartUploadField`/`executeUploadAttemptField`) rather
than a query-string parameter.

Batch 2 (this PR) also added `RecordProbedKey` coverage to four
endpoint-shaped probes that have no per-parameter fuzz matrix
(`active_xxe.go`, `clickjacking_probe.go`, `deserialization_probe.go`,
`dom_xss_probe.go`) and to the three HTTP-method-focused sub-probes in
`http_methods_probe.go` (`probeOptionsMethod`, `probeTraceMethod`,
`probeVerbOverride`), matching the `param: ➖` treatment already used for
`active_xxe.go` and `cloud_storage_probe.go`.

## Appendix — audit one-liner

```sh
grep -L 'sqliDynamicParams\|DiscoveredParamsFor\|AllDiscoveredParams\|RecordProbedKey' \
  backend/internal/scanner/*_probe.go backend/internal/scanner/active_*.go
```
