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

Snapshot generated 2026-07-06 (Batch 3 — all rows complete).

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
| `deserialization_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoint+body-shaped like `active_xxe.go` (fixed serialized-format preambles, no per-parameter fuzz matrix); `RecordProbedKey` added to the active-probe and passive-observation loops. Now re-invoked by the gap-requeue pass (via its `RunInput`-adapted call) for high-ROI unprobed endpoints. |
| `dns_san_probe.go` | ➖ | ➖ | ➖ | ➖ | Certificate metadata; no HTTP surface. |
| `dom_xss_probe.go` | ✅ | ➖ | ✅ | ✅ | Fragment sink (location.hash), no query-parameter matrix; `RecordProbedKey` added per navigated endpoint. Now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `file_upload_probe.go` | ✅ | ✅ | ✅ | ✅ | Migrated: miner-surfaced upload-field names are merged in front of the built-in `"file"` field via the new `buildMultipartUploadField`/`executeUploadAttemptField` helpers; `RecordProbedKey` records `(POST, url, fieldName)`. Now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `formula_injection.go` | ✅ | ✅ | ✅ | ✅ | Migrated: miner params merged in front of `formulaProbeParams`; `RecordProbedKey` added. Now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `http_methods_probe.go` | ✅ | ➖ | ✅ | ✅ | `RecordProbedKey` added to `probeOptionsMethod` (OPTIONS), `probeTraceMethod` (TRACE), and `probeVerbOverride` (baseline GET + tunnelled DELETE), so the gap detector can see per-method coverage. Now re-invoked by the gap-requeue pass for high-ROI unprobed endpoints. |
| `jwt_probe.go` | ➖ | ➖ | ✅ | ➖ | Single-token/session check (no URL enumeration); `RecordProbedKey` records the target as probed. Gap-requeue not applicable — there is no unprobed-endpoint surface to re-walk. |
| `jwt_advanced_probe.go` | ➖ | ➖ | ✅ | ➖ | Single-token/session check like `jwt_probe.go`; `RecordProbedKey` added. Gap-requeue not applicable. |
| `login_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoints already discovered via `loginDiscoverEndpoints(..., options.SeedRuntimeEndpoints, ...)`; `RecordProbedKey` records every discovered login/registration endpoint. Now re-invoked by the gap-requeue pass (`RunLoginProbe`) for high-ROI unprobed endpoints. Credential/field fuzzing is fixed-shape (username/password), not a generic param wordlist, so `param` is ➖. |
| `magic_link_invite_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoints already discovered via `magicLinkDiscoverEndpoints(..., options.SeedRuntimeEndpoints, ...)`; `RecordProbedKey` records every discovered magic-link/invite/account-link endpoint. Now re-invoked by the gap-requeue pass (`RunMagicLinkProbe`). |
| `mfa_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoints already discovered via `mfaDiscoverEndpoints(..., options.SeedRuntimeEndpoints, ...)`; `RecordProbedKey` records every discovered MFA/backup-code/step-up endpoint. Now re-invoked by the gap-requeue pass (`RunMFAProbe`). |
| `oauth_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoints already discovered via `oauthDiscoverEndpoints(..., options.SeedRuntimeEndpoints, ...)`; `RecordProbedKey` records each authorize endpoint under the `redirect_uri` key. Now re-invoked by the gap-requeue pass (`RunOAuthProbe`). |
| `oauth_session_probe.go` | ✅ | ➖ | ✅ | ✅ | Token/authorize endpoints already discovered via `oauthDiscoverTokenEndpoints`/`oauthDiscoverAuthorizeEndpoints` (both seeded); `RecordProbedKey` added for both. Now re-invoked by the gap-requeue pass (`RunOAuthSessionProbe`). |
| `password_reset_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoints already discovered via `collectPWResetCandidates(..., input.Options.SeedRuntimeEndpoints, ...)`; `RecordProbedKey` records every candidate under the `email` key. Now re-invoked by the gap-requeue pass (`runPasswordResetProbe`). |
| `postmessage_probe.go` | ➖ | ➖ | ➖ | ➖ | Browser-side observation. |
| `reverse_tabnabbing_probe.go` | ➖ | ➖ | ✅ | ➖ | Zero-request passive probe over already-fetched `bodyText`; `RecordProbedKey` records the page URL. No endpoint enumeration, so gap-requeue is not applicable. |
| `saml_probe.go` | ✅ | ➖ | ✅ | ✅ | `samlDiscoverEndpoints` now also accepts `options.SeedRuntimeEndpoints` (merged when a seeded URL matches the ACS/metadata path set), matching the pattern used by the other auth-flow probes; `RecordProbedKey` added for ACS and metadata endpoints. Now re-invoked by the gap-requeue pass (`RunSAMLProbe`). |
| `security_headers_probe.go` | ➖ | ➖ | ✅ | ➖ | Header-only, single-URL check against the already-fetched baseline response; `RecordProbedKey` records the target. Gap-requeue not applicable (no per-endpoint fuzz loop). |
| `session_lifecycle_probe.go` | ✅ | ➖ | ✅ | ✅ | Login/logout/protected/password-change endpoints already discovered via the seeded `sessionDiscover*Endpoints` helpers; `RecordProbedKey` (via the new `recordSessionEndpoints` helper) added at every discovery call site plus the initial cookie-baseline GET. Now re-invoked by the gap-requeue pass (`RunSessionLifecycleProbe`). |
| `smtp_injection_probe.go` | ✅ | ✅ | ✅ | ✅ | Migrated: miner params merged in front of `smtpEmailParams` via `phase2DynamicParams`/`phase2ProbeParams`; `RecordProbedKey` added per (endpoint, param) attempt. Now re-invoked by the gap-requeue pass. |
| `ssi_injection_probe.go` | ✅ | ✅ | ✅ | ✅ | Migrated: miner params merged in front of `ssiParams`; `RecordProbedKey` added per (endpoint, param) attempt. Now re-invoked by the gap-requeue pass. |
| `tls_config_probe.go` | ➖ | ➖ | ➖ | ➖ | Transport-level. |
| `ui_simulation_probe.go` | ➖ | ➖ | ➖ | ➖ | Browser-only. |
| `verbose_error_probe.go` | ✅ | ➖ | ✅ | ✅ | `malformedInputs` are fixed error-triggering payload shapes (SQL syntax, null byte, oversized int), not generic parameter names, so miner-param merging doesn't apply the same way as a query-fuzz wordlist (`param` ➖); `RecordProbedKey` records every (method, url, param) attempt. Now re-invoked by the gap-requeue pass. |
| `websocket_probe.go` | ✅ | ➖ | ✅ | ✅ | `websocketCandidates` now also merges any `ws://`/`wss://` URL present in `options.SeedRuntimeEndpoints`; `RecordProbedKey` records every handshake URL attempted. Now re-invoked by the gap-requeue pass. |
| `xssi_jsonp_probe.go` | ✅ | ✅ | ✅ | ✅ | Migrated: miner params merged in front of `jsonpCallbackParams`; `RecordProbedKey` added for both the JSONP-callback loop and the XSSI-array check. Now re-invoked by the gap-requeue pass. |
| `cache_poisoning.go` | ➖ | ➖ | ✅ | ✅ | Single-URL header-injection check (no per-parameter loop, so `inv`/`param` ➖); `RecordProbedKey(GET, target, "")` added at probe entry. `gapReQueueCachePoisoningProbe` (budget 5) re-runs it against high-ROI gap URLs, mirroring `gapReQueueClickjackingProbe`. |
| `css_injection_probe.go` | ✅ | ➖ | ✅ | ✅ | Consumes `SeedRuntimeEndpoints` for candidate URLs; payload is a fixed CSS breakout string (not a per-parameter wordlist), so `param` ➖; `RecordProbedKey(GET, probeURL, param)` added in the per-candidate loop. Now re-invoked by the gap-requeue pass. |
| `csp_analysis.go` | ➖ | ➖ | ✅ | ✅ | Passive header-only check; `RecordProbedKey(GET, u, "")` added in `runCSPAnalysisSeeded`. `scanner.go` now calls `runCSPAnalysisSeeded` (bound 10) so seeded runtime endpoints also get per-path CSP coverage. |
| `dom_clobbering_probe.go` | ✅ | ➖ | ✅ | ✅ | Consumes `SeedRuntimeEndpoints`; payload is a fixed named-element injection (not a param wordlist), so `param` ➖; `RecordProbedKey(GET, testURL, param)` added in the per-candidate loop. Now re-invoked by the gap-requeue pass. |
| `rate_limit_probe.go` | ✅ | ➖ | ✅ | ✅ | Endpoints discovered via `loginDiscoverEndpoints` + `SeedRuntimeEndpoints`; fixed JSON burst payload (not a query-param wordlist), so `param` ➖; `RecordProbedKey(POST, ep, "")` added per candidate. Now re-invoked by the gap-requeue pass. |
| `reflected_file_download_probe.go` | ✅ | ➖ | ✅ | ✅ | Consumes `SeedRuntimeEndpoints`; parameter list is fixed (`rfdParams`), so `param` ➖; `RecordProbedKey(GET, probeURL, param)` added in the per-candidate loop. Now re-invoked by the gap-requeue pass. |
| `request_smuggling.go` | ➖ | ➖ | ✅ | ➖ | Single-URL raw-socket timing check (no per-endpoint enumeration, no param loop); `RecordProbedKey("POST", target, "")` added at probe entry. Gap-requeue not applicable — the probe already runs against a single target with no enumerable surface to re-walk. |
| `sri_probe.go` | ➖ | ➖ | ✅ | ✅ | Passive body scan; `RecordProbedKey("GET", target, "")` added at entry. `runSRISeeded` (bound 10) now fetches seeded endpoints for per-page SRI coverage; `scanner.go` calls it after the baseline. |
| `vhost_discovery.go` | ➖ | ➖ | ✅ | ✅ | Single-URL Host-header rotation (no per-parameter loop, so `inv`/`param` ➖); `RecordProbedKey(GET, target, "")` added at probe entry. `gapReQueueVhostProbe` (budget 5) re-runs it against high-ROI gap URLs. |
| `xslt_injection_probe.go` | ✅ | ➖ | ✅ | ✅ | XSLT candidates are URL-shaped (no per-parameter query fuzz), so `param` ➖; `RecordProbedKey(POST, ep, "")` added in both the OAST and file-read candidate loops. Now re-invoked by the gap-requeue pass. |
| `zip_slip_probe.go` | ✅ | ➖ | ✅ | ✅ | Upload endpoints discovered via `discoverUploadEndpoints` + `SeedRuntimeEndpoints`; archive entry-names are fixed traversal paths (not a query-param wordlist), so `param` ➖; `RecordProbedKey(POST, ep, "")` added per candidate. Now re-invoked by the gap-requeue pass. |

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

Follow the same three steps for any future new probe. Header / cookie /
transport probes only need step 3.

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

Batch 2 also added `RecordProbedKey` coverage to four
endpoint-shaped probes that have no per-parameter fuzz matrix
(`active_xxe.go`, `clickjacking_probe.go`, `deserialization_probe.go`,
`dom_xss_probe.go`) and to the three HTTP-method-focused sub-probes in
`http_methods_probe.go` (`probeOptionsMethod`, `probeTraceMethod`,
`probeVerbOverride`), matching the `param: ➖` treatment already used for
`active_xxe.go` and `cloud_storage_probe.go`.

Batch 3 closed out every remaining row in the table:

- Extended the `gap` control (`runGapReQueuePass`) to the five probes
  that already consumed `SeedRuntimeEndpoints` but weren't yet
  re-invoked on the second pass (`deserialization_probe.go`,
  `dom_xss_probe.go`, `file_upload_probe.go`, `formula_injection.go`,
  `http_methods_probe.go`), plus every auth-flow and remaining
  injection probe below.
- Migrated the three remaining fixed-wordlist injection probes
  (`smtp_injection_probe.go`, `ssi_injection_probe.go`,
  `xssi_jsonp_probe.go`) onto `phase2DynamicParams`/`phase2ProbeParams`,
  matching the `active_sqli.go` reference pattern.
- Added `RecordProbedKey` coverage — and, where the probe didn't
  already consume `SeedRuntimeEndpoints`/miner-discovered endpoints,
  extended endpoint discovery to include them — for every auth-flow
  probe (`login_probe.go`, `magic_link_invite_probe.go`, `mfa_probe.go`,
  `oauth_probe.go`, `oauth_session_probe.go`, `password_reset_probe.go`,
  `saml_probe.go`, `session_lifecycle_probe.go`), the two JWT probes
  (`jwt_probe.go`, `jwt_advanced_probe.go`), and the remaining
  header/response-shape probes (`reverse_tabnabbing_probe.go`,
  `security_headers_probe.go`, `verbose_error_probe.go`,
  `websocket_probe.go`).
- `saml_probe.go`'s `samlDiscoverEndpoints` now takes a `seeded []string`
  parameter (mirroring `loginDiscoverEndpoints`/`mfaDiscoverEndpoints`/
  etc.) so runtime-XHR/miner-surfaced ACS and metadata URLs are folded
  into the inventory.
- `session_lifecycle_probe.go` gained a `recordSessionEndpoints` helper
  so its several `sessionDiscover*Endpoints` call sites all funnel
  through one `RecordProbedKey` call.
- `jwt_probe.go`, `jwt_advanced_probe.go`, `reverse_tabnabbing_probe.go`,
  and `security_headers_probe.go` operate on a single target/token
  rather than an enumerable endpoint list, so `inv`, `param`, and `gap`
  remain ➖ for those four — there is no unprobed-surface list for the
  gap-requeue pass to walk.

Every row in the table is now ✅ or ➖ — no `⚠️` rows remain.

Batch 4 (this PR) added the 12 probes that existed in the scanner but were
previously absent from the audit table:

- Added `RecordProbedKey` to the per-candidate loops of `css_injection_probe.go`,
  `rate_limit_probe.go`, `reflected_file_download_probe.go`,
  `xslt_injection_probe.go`, `zip_slip_probe.go`, and `dom_clobbering_probe.go`
  and wired all six into `runGapReQueuePass` so late-discovered endpoints receive
  a bounded second probe pass.
- Added `RecordProbedKey` to the single-URL probes `cache_poisoning.go`,
  `request_smuggling.go`, and `vhost_discovery.go`; added
  `gapReQueueCachePoisoningProbe` and `gapReQueueVhostProbe` (each bounded to
  5 URLs) in `phase2_gap_requeue.go` so late-discovered pages also get cache-
  poisoning and vhost-discovery coverage.
- Added `RecordProbedKey` to `sri_probe.go` and introduced `runSRISeeded`
  (bound 10) for per-page SRI coverage of seeded runtime endpoints.
- Added `runCSPAnalysisSeeded` (bound 10) to `csp_analysis.go` and called it
  from `scanner.go` so seeded runtime endpoints receive per-path CSP analysis.

## Appendix — audit one-liner

```sh
grep -L 'sqliDynamicParams\|DiscoveredParamsFor\|AllDiscoveredParams\|RecordProbedKey' \
  backend/internal/scanner/*_probe.go backend/internal/scanner/active_*.go
```
