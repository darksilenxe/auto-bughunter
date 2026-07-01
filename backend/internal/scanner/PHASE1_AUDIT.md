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

| Probe file | gate | refl | base | verify | Notes |
| --- | :---: | :---: | :---: | :---: | --- |
| `active_cors.go` | ✅ | ➖ | ✅ | ✅ | Full Phase 1 migration: baseline no-Origin control, `SubmitVerifiedFinding` with canonicalised "cors" category (external label `cors_redirect` preserved on emitted finding), `EvidenceHeaderDelta` + `EvidenceReflection` signals, `responseShape` tag. |
| `active_graphql_introspection.go` | ➖ | ➖ | ⚠️ | ⚠️ | Introspection response is JSON; add JSON-shape gate for reporting. |
| `active_ldap_injection.go` | ⚠️ | ⚠️ | ✅ | ⚠️ | Add reflection classifier for LDAP error echoes; verify High findings. |
| `active_nosqli.go` | ⚠️ | ⚠️ | ✅ | ⚠️ | Add JSON-shape gate; differential re-verify for confirmed cases. |
| `active_open_redirect.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Use `ContextURL` classifier; require `PayloadEscapesContext(ContextURL, payload)`. |
| `active_path_traversal.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Add binary bail-out (`IsBinaryShape`); differential re-verify High/Critical. |
| `active_prompt_injection.go` | ⚠️ | ⚠️ | ✅ | ⚠️ | JSON-shape gate for LLM APIs; reflection classifier for echoed prompts. |
| `active_prototype_pollution.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Require `IsJSONShape`; differential re-verify. |
| `active_sqli.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Binary bail-out; control baseline for timing; differential re-verify for time-based signal. |
| `active_ssti.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | Reflection-context aware payload selection; differential re-verify for arithmetic markers. |
| `active_xpath_injection.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | XML-shape gate for XPath error surfaces. |
| `active_xss.go` | ✅ | ✅ | ✅ | ✅ | Full Phase 1 migration: response-shape tag, `ClassifyReflectionContext` + `PayloadEscapesContext` gate for High/Critical, two-control baseline, `SubmitVerifiedFinding`, and `DifferentialReVerify`. |
| `active_xxe.go` | ⚠️ | ➖ | ✅ | ⚠️ | Require `IsXMLShape` on the probed endpoint's response. |
| `browser_storage_probe.go` | ➖ | ➖ | ➖ | ⚠️ | Browser-side observation; verify High findings. |
| `clickjacking_probe.go` | ✅ | ➖ | ⚠️ | ⚠️ | HTML gate present; add differential baseline (framed vs unframed control). |
| `cloud_storage_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Bucket enumeration — add response-shape evidence tag. |
| `command_injection_probe.go` | ⚠️ | ⚠️ | ✅ | ⚠️ | Binary bail-out; differential re-verify time-based signal. |
| `cross_domain_policy_probe.go` | ⚠️ | ➖ | ➖ | ➖ | Require XML shape on `crossdomain.xml`. |
| `csrf_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | Add control (token-stripped) request to establish baseline. |
| `dangling_markup.go` | ✅ | ✅ | ⚠️ | ⚠️ | Migrated in this PR as reference template. |
| `deserialization_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Binary bail-out; differential re-verify. |
| `dns_san_probe.go` | ➖ | ➖ | ➖ | ➖ | DNS observation, no probe body. |
| `dom_xss_probe.go` | ⚠️ | ⚠️ | ✅ | ⚠️ | HTML gate + reflection classifier for the injected fragment. |
| `file_upload_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Response-shape tag; differential (allowed vs blocked baseline). |
| `formula_injection.go` | ✅ | ➖ | ⚠️ | ⚠️ | Migrated in this PR (binary bail-out + response-shape tag). |
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
| `reverse_tabnabbing_probe.go` | ✅ | ➖ | ➖ | ➖ | HTML shape only. |
| `saml_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | XML-shape gate on SAML responses. |
| `security_headers_probe.go` | ➖ | ➖ | ✅ | ➖ | Header-only, no reflection. |
| `session_lifecycle_probe.go` | ➖ | ➖ | ✅ | ⚠️ | Verify High findings. |
| `smtp_injection_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | CRLF classifier via `ContextHeader`; differential re-verify. |
| `ssi_injection_probe.go` | ⚠️ | ⚠️ | ⚠️ | ⚠️ | HTML-shape gate + arithmetic marker differential. |
| `tls_config_probe.go` | ➖ | ➖ | ➖ | ➖ | TLS handshake, no body. |
| `ui_simulation_probe.go` | ➖ | ➖ | ➖ | ➖ | Instrumented browser interaction. |
| `verbose_error_probe.go` | ⚠️ | ➖ | ⚠️ | ⚠️ | Binary bail-out; differential (benign-marker) verify. |
| `websocket_probe.go` | ➖ | ➖ | ⚠️ | ⚠️ | WebSocket frame classifier + baseline. |
| `xssi_jsonp_probe.go` | ⚠️ | ➖ | ➖ | ⚠️ | JSON/JavaScript-shape gate. |

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
