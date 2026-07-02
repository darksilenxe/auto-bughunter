# Phase 1 audit: false-positive-reduction status per probe

This document tracks the per-probe rollout of the four Phase 1 controls
introduced in the shared modules:

| Control | Module / API |
| --- | --- |
| **gate** — content-type / response-shape gate | `probe_gates.go` (`IsHTMLShape`, `IsJSONShape`, `IsXMLShape`, `IsBinaryShape`, `ClassifyResponseShape`) |
| **refl** — reflection-context classifier | `reflection_context.go` (`ClassifyReflectionContext`, `PayloadEscapesContext`) |
| **base** — control baseline | `pre_report_verify.go` (`CaptureTwoControlBaselines`, `ExceedsControlVariance`) |
| **verify** — pre-report + differential re-verify | `pre_report_verify.go` (`SubmitVerifiedFinding`) + `pre_report_differential.go` (`DifferentialReVerify`, `RequiresUnconditionalVerification`) |

Every candidate finding also passes through process-wide clustering
(`findings_cluster.ClusterFindings`, wired into `enrichFindings`) and is
counted by `GetClusterMetrics()` → `AutomationMetrics.Extra.clusterRatio`.

## Legend

- ✅ Applied.
- ➖ Not applicable (e.g. header-only probe has no reflected payload).
- ⚠️ **TODO** — must be added in a follow-up PR.

## Audit table

Snapshot generated 2026-07-01. Regenerate with the audit one-liner in
the appendix.

References landed so far:

- `dangling_markup.go` and `formula_injection.go` — original Phase 1
  reference migrations (shape gate + reflection-context / binary
  bail-out).
- `active_xss.go` — first full four-control migration
  (shape tag + reflection-context escape gate + two-control baseline
  + `SubmitVerifiedFinding` + `DifferentialReVerify`).
- Batch A injection probes landed: `active_sqli.go`, `active_ssti.go`,
  `active_xpath_injection.go`, `active_path_traversal.go`, `active_xxe.go`,
  `command_injection_probe.go`, `deserialization_probe.go`,
  `smtp_injection_probe.go`, and `ssi_injection_probe.go`.
- Batch B reflection / response-shape probes landed:
  `dangling_markup.go`, `formula_injection.go`, `verbose_error_probe.go`,
  `cross_domain_policy_probe.go`, and `xssi_jsonp_probe.go`.
- `csrf_probe.go` — Phase 2 FN-reduction migration
  (SurfaceInventory + method/content-type/token-carrier/Origin matrix,
  bypass variants for empty-value / method-override / duplicate-token /
  default-token, unauthenticated baseline + two-control replay +
  `SubmitVerifiedFinding`). `csrf` is now a canonical proof-policy
  category.
- PayloadsAllTheThings/HackTricks technique-gap batch landed:
  `zip_slip_probe.go`, `xslt_injection_probe.go`, `dns_rebinding_probe.go`,
  `dom_clobbering_probe.go`, `rate_limit_probe.go`, and `redos_probe.go` —
  new active probes covering previously-uncovered PATT/HackTricks
  categories (Zip Slip, XSLT Injection, SSRF DNS Rebinding, DOM
  Clobbering, dedicated Brute Force/Rate Limit, and ReDoS). See
  `frontend/src/lib/webVulnerabilityCoverage.js`,
  `security-knowledge/sources/corpus_sources.json`, and
  `backend/internal/hacktricks/techniques.go` for the matching
  reference/corpus/command-template entries.

| Probe file | gate | refl | base | verify | Notes |
| --- | :---: | :---: | :---: | :---: | --- |
| `active_cors.go` | ✅ | ➖ | ✅ | ✅ | Full Phase 1 migration: baseline no-Origin control, `SubmitVerifiedFinding` with canonicalised "cors" category (external label `cors_redirect` preserved on emitted finding), `EvidenceHeaderDelta` + `EvidenceReflection` signals, `responseShape` tag. |
| `active_graphql_introspection.go` | ✅ | ➖ | ➖ | ➖ | JSON-shape gate on introspection response + `responseShape` tag; category "api" has no proof-policy rules, so verify is intentionally not routed. |
| `active_ldap_injection.go` | ✅ | ➖ | ✅ | ✅ | Binary-shape bail-out, `responseShape` tag, and `DifferentialReVerify` (benign-payload oracle strips static-error-page FPs). Category "injection" has no proof-policy rules so `SubmitVerifiedFinding` is intentionally skipped. |
| `active_nosqli.go` | ✅ | ➖ | ✅ | ✅ | Full Phase 1 migration: binary-shape bail-out, `SubmitVerifiedFinding` with canonicalised "nosqli" category (external label `input-validation` preserved), 3 evidence signals to meet strict-emission minimum, and `DifferentialReVerify` that strips static-error-page false positives. |
| `active_open_redirect.go` | ➖ | ✅ | ✅ | ✅ | Full Phase 1 migration: `CaptureTwoControlBaselines` suppresses static off-host redirects, `DifferentialReVerify` (benign-path oracle) suppresses reflection-into-Location noise, `SubmitVerifiedFinding` with canonical "open_redirect" alias (external "input-validation" preserved) and 3 evidence signals. |
| `active_path_traversal.go` | ✅ | ➖ | ✅ | ✅ | Binary bail-out + `responseShape`, clean filename baselines, differential benign filename replay, and `SubmitVerifiedFinding` with canonical `path_traversal` (external label preserved). |
| `active_prompt_injection.go` | ✅ | ➖ | ➖ | ✅ | Full Phase 1 migration (verify skipped — no proof-policy for "prompt-injection"): `IsBinaryShape` bail-out and `responseShape` tag on direct-hit response, `DifferentialReVerify` (benign "hello" oracle) suppresses cached/static echoes of `PWNMARKER7731`. Indirect (stored) path unchanged. |
| `active_prototype_pollution.go` | ✅ | ➖ | ➖ | ✅ | Full Phase 1 migration (verify skipped — no proof-policy for "prototype-pollution"): `IsBinaryShape` bail-out and `responseShape` tag on follow-up response, `DifferentialReVerify` on both query-string and JSON-body branches (benign payload replay confirms marker is not statically echoed). |
| `active_sqli.go` | ✅ | ➖ | ✅ | ✅ | Binary bail-out + `responseShape`, benign parameter baselines, differential benign replay, and `SubmitVerifiedFinding` with canonical `sqli` (external label preserved). |
| `active_ssti.go` | ✅ | ✅ | ✅ | ✅ | Binary bail-out + evaluated-marker reflection context, benign template baselines, differential benign replay, and `SubmitVerifiedFinding` with canonical `ssti` (external label preserved). |
| `active_xpath_injection.go` | ✅ | ➖ | ✅ | ✅ | XML response-shape gate, benign XPath baselines, and differential benign replay; no proof-policy category, so `SubmitVerifiedFinding` remains skipped. |
| `active_xss.go` | ✅ | ✅ | ✅ | ✅ | Full Phase 1 migration: response-shape tag, `ClassifyReflectionContext` + `PayloadEscapesContext` gate for High/Critical, two-control baseline, `SubmitVerifiedFinding`, and `DifferentialReVerify`. |
| `active_xxe.go` | ✅ | ➖ | ✅ | ✅ | XML response-shape gate on reflected/error responses, benign XML baselines, differential benign XML replay, and `SubmitVerifiedFinding` with canonical `xxe` (external label preserved). |
| `browser_storage_probe.go` | ➖ | ➖ | ➖ | ⚠️ | Browser-side observation; verify High findings. |
| `clickjacking_probe.go` | ✅ | ➖ | ⚠️ | ⚠️ | HTML gate present; add differential baseline (framed vs unframed control). |
| `cloud_storage_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Bucket enumeration — add response-shape evidence tag. |
| `command_injection_probe.go` | ✅ | ✅ | ✅ | ✅ | Binary bail-out + marker context, two-control latency/body baselines, differential output/timing replay, and `SubmitVerifiedFinding` with `AllowNoReplayEmission` (no proof-policy coverage for `command-injection`). |
| `cross_domain_policy_probe.go` | ✅ | ➖ | ➖ | ➖ | XML shape gate on well-known policy paths; findings tag `responseShape`. |
| `csrf_probe.go` | ➖ | ➖ | ✅ | ✅ | Unauth baseline suppresses public endpoints; two-control replay rejects flakes; routes through `SubmitVerifiedFinding` (csrf is a canonical proof-policy category). |
| `dangling_markup.go` | ✅ | ✅ | ✅ | ✅ | Batch B: HTML shape gate + reflection-context sink gate, control-value baseline, and differential benign replay confirm the marker is payload-controlled. Category "injection" has no proof-policy so `SubmitVerifiedFinding` remains skipped. |
| `deserialization_probe.go` | ✅ | ➖ | ✅ | ✅ | Binary bail-out on active/passive responses, benign serialized-body baselines, and differential benign-body replay; no proof-policy category, so `SubmitVerifiedFinding` remains skipped. |
| `dns_san_probe.go` | ➖ | ➖ | ➖ | ➖ | DNS observation, no probe body. |
| `dns_rebinding_probe.go` | ➖ | ➖ | ➖ | ➖ | Control-request differential (safe external URL vs loopback-resolving hostname) + internal-signature match; category "input-validation" has no dedicated proof-policy rule set for this probe. |
| `dom_clobbering_probe.go` | ✅ | ✅ | ✅ | ✅ | Full Phase 1 migration: HTML-shape gate, literal unescaped-tag reflection check, two-control baseline, `SubmitVerifiedFinding` with canonical `xss` alias (external label `dom-clobbering`-style category preserved), and `DifferentialReVerify`. |
| `dom_xss_probe.go` | ⚠️ | ⚠️ | ✅ | ⚠️ | HTML gate + reflection classifier for the injected fragment. |
| `file_upload_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Response-shape tag; differential (allowed vs blocked baseline). |
| `formula_injection.go` | ✅ | ✅ | ✅ | ✅ | Batch B: binary bail-out + `responseShape` tag, reflection-context evidence, benign parameter baseline, and differential benign replay strip static echoes of the `=` marker. Category "injection" has no proof-policy so `SubmitVerifiedFinding` remains skipped. |
| `http_methods_probe.go` | ➖ | ➖ | ✅ | ⚠️ | Header-only probe. |
| `jwt_advanced_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Auth-token probe; add differential (unsigned vs signed control). |
| `jwt_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Same as above. |
| `login_probe.go` | ➖ | ➖ | ➖ | ➖ | Auth setup, not a finding source. |
| `magic_link_invite_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Add control baseline (invalid-token control). |
| `mfa_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Differential (no-MFA vs MFA control). |
| `oauth_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Differential (redirect_uri stripped vs benign control). |
| `oauth_session_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Same as above. |
| `password_reset_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Differential (reset-token stripped vs benign control). |
| `postmessage_probe.go` | ✅ | ⚠️ | ➖ | ⚠️ | Browser postMessage; classify origin echo context. |
| `rate_limit_probe.go` | ➖ | ➖ | ➖ | ➖ | Bounded request-burst throttling check (429/423/Retry-After/lockout signal) across password-reset/registration/OTP/coupon endpoints; control-absence finding, mirrors `login_probe.go`'s brute-force check convention (no `SubmitVerifiedFinding` — same as that reference). |
| `redos_probe.go` | ➖ | ➖ | ✅ | ✅ | Catastrophic-backtracking trigger strings, two-control timing baseline (`phase1TimingExceeds`), `DifferentialReVerify` timing oracle, and `SubmitVerifiedFinding` (category `redos`, no canonical proof-policy alias yet). |
| `reverse_tabnabbing_probe.go` | ✅ | ➖ | ➖ | ➖ | HTML shape only. |
| `saml_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | XML-shape gate on SAML responses. |
| `security_headers_probe.go` | ➖ | ➖ | ✅ | ➖ | Header-only, no reflection. |
| `session_lifecycle_probe.go` | ➖ | ➖ | ✅ | ⚠️ | Verify High findings. |
| `smtp_injection_probe.go` | ✅ | ✅ | ✅ | ✅ | Binary bail-out + SMTP marker context, clean form baselines, and differential clean-address replay; no proof-policy category and error finding is Medium, so `SubmitVerifiedFinding` remains skipped. |
| `ssi_injection_probe.go` | ✅ | ✅ | ✅ | ✅ | HTML response-shape gate, SSI marker context, clean parameter baselines, and differential benign replay; no proof-policy category, so `SubmitVerifiedFinding` remains skipped. |
| `tls_config_probe.go` | ➖ | ➖ | ➖ | ➖ | TLS handshake, no body. |
| `ui_simulation_probe.go` | ➖ | ➖ | ➖ | ➖ | Instrumented browser interaction. |
| `verbose_error_probe.go` | ✅ | ➖ | ✅ | ✅ | Batch B: binary bail-out on 4xx/5xx bodies with `responseShape` tag, and a clean-request baseline that suppresses endpoints whose static error page already matches the signature. |
| `websocket_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | WebSocket frame classifier + baseline. |
| `xslt_injection_probe.go` | ✅ | ➖ | ✅ | ✅ | XSLT-keyword candidate discovery, OAST out-of-band `document()` dereference + reflected-file-read phases (mirrors `active_xxe.go`), benign-stylesheet baseline, differential benign replay, and `SubmitVerifiedFinding` with canonical `xxe` alias (external label preserved). |
| `xssi_jsonp_probe.go` | ✅ | ➖ | ➖ | ➖ | Batch B: JavaScript/JSON shape gate on both the JSONP callback probe and the top-level array probe; findings tag `responseShape`. |
| `zip_slip_probe.go` | ➖ | ➖ | ➖ | ➖ | Reuses `file_upload_probe.go`'s endpoint discovery; control archive vs traversal-entry archive differential + rejection-signature check (no filesystem-level confirmation possible from a black-box scanner). |

## What landed in this PR

- Shared modules: `probe_gates.go`, `reflection_context.go`, `findings_cluster.go`, `pre_report_differential.go` with unit tests.
- Aggregator: `enrichFindings` now clusters findings via `scanner.ClusterFindings`.
- Metrics: `AutomationMetrics.Extra` gains `clusterTotalIn`, `clusterTotalOut`, `clusterClustered`, `clusterRatio`, `differentialTotal`, `differentialConfirmed`, `differentialFPStripped`, `differentialFPBenign`, `differentialExecErrors`, `differentialConfirmedRate`.
- Reference migrations: `dangling_markup.go` (gate + reflection classifier) and `formula_injection.go` (binary bail-out + response-shape tagging).

## Follow-up PRs (rollout guidance)

Each `⚠️` entry should be migrated with roughly the following pattern:

1. Before reporting, call the appropriate shape gate:
   - HTML sink probes → `if !IsHTMLShape(resp.Header) { continue }`
   - JSON-only probes → `if !IsJSONShape(resp.Header) { continue }`
   - XML-only probes → `if !IsXMLShape(resp.Header) { continue }`
   - Reflection probes → `if IsBinaryShape(resp.Header) { continue }` and always tag `EvidenceFields["responseShape"] = ClassifyResponseShape(resp.Header).String()`.
2. For reflected-input findings, classify context with `ClassifyReflectionContext(body, marker)` and require `PayloadEscapesContext(ctx, payload)` before reporting High/Critical.
3. Where no control baseline exists, capture one via `CaptureTwoControlBaselines` and gate with `ExceedsControlVariance`.
4. For every candidate where `RequiresUnconditionalVerification(candidate.Severity)` is true, route through `SubmitVerifiedFinding`, and — when a probe-specific oracle is available — call `DifferentialReVerify` and `AttachDifferentialEvidence`.

## Appendix — regenerate the audit

```
for f in $(ls backend/internal/scanner/ | grep -E "^active_.*\.go$|_probe\.go$" | grep -v _test); do
  p="backend/internal/scanner/$f"
  gate="no"; refl="no"; base="no"; verify="no"
  grep -q "IsHTMLShape\|IsJSONShape\|IsXMLShape\|IsBinaryShape\|isHTMLLikeContentType\|ClassifyResponseShape" "$p" && gate="yes"
  grep -q "ClassifyReflectionContext\|PayloadEscapesContext" "$p" && refl="yes"
  grep -q "CaptureTwoControlBaselines\|BaselineControls" "$p" && base="yes"
  grep -q "SubmitVerifiedFinding\|DifferentialReVerify" "$p" && verify="yes"
  printf "%-38s gate=%s refl=%s base=%s verify=%s\n" "$f" "$gate" "$refl" "$base" "$verify"
done
```
