# Phase 3 audit: evidence-schema status per probe

This document tracks the per-probe rollout of the Phase 3 evidence
schema introduced in the shared modules:

| Control | Module / API |
| --- | --- |
| **schema** — typed EvidenceRecord | `evidence_schema.go` (`EvidenceRecord`, `Validate`) |
| **norm** — free-form → typed coercion | `evidence_normalizer.go` (`NormalizeEvidence`) |
| **stamp** — writes `verifiedBy=<oracle>@<version>` | `pre_report_verify.go` (`SubmitVerifiedFinding`) |

`enrichFindings` runs `NormalizeEvidence` on every finding before
clustering, tags `EvidenceFields["evidenceQuality"] = "valid"` or
`"incomplete"`, and increments `scanner.GetEvidenceMetrics()` so
`AutomationMetrics.Extra` exposes `evidenceValid`,
`evidenceIncomplete`, `evidenceValidRatio`, and
`evidenceMissing<Field>` keys.

The strict-reporting filter (`handlers_report.go`) suppresses findings
whose `evidenceQuality` is `"incomplete"` when strict mode is on.

## Legend

- ✅ Emits a Phase 3-compliant EvidenceRecord (all category-required
  fields populated).
- ➖ Not applicable (governance / metadata finding — evidence schema is
  identity/URL only).
- ⚠️ **TODO** — probe currently ships free-form evidence; the
  normalizer will still produce a record but Validate may tag it as
  incomplete.

## Audit table

Snapshot generated 2026-07-01. Batch 1 (first 10 ⚠️ rows: `active_cors.go`
through `active_ssti.go`) migrated to `schema` ✅ on 2026-07-04.

| Probe file | schema | stamp | Notes |
| --- | :---: | :---: | --- |
| `active_cors.go` | ✅ | ⚠️ | Migrated: `payloadClass=cors-origin-reflection`, `url`, `oracleName` added. |
| `active_graphql_introspection.go` | ✅ | ⚠️ | Migrated: `payloadClass=graphql-introspection`, `oracleName` added. |
| `active_ldap_injection.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=ldap-injection` added. |
| `active_nosqli.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=nosql-operator` added. |
| `active_open_redirect.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=open-redirect` added. |
| `active_path_traversal.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=path-traversal` added. |
| `active_prompt_injection.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=prompt-injection` added. |
| `active_prototype_pollution.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=proto-pollution` added. |
| `active_sqli.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=sqli-error` added. |
| `active_ssti.go` | ✅ | ⚠️ | Migrated: `param`, `payloadClass=ssti` added. |
| `active_xpath_injection.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=xpath-injection`. |
| `active_xss.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=xss-reflected`, `reflectionContext`. |
| `active_xxe.go` | ⚠️ | ⚠️ | Add `payloadClass=xxe`, `responseShape=xml`. |
| `browser_storage_probe.go` | ➖ | ➖ | Browser observation. |
| `clickjacking_probe.go` | ⚠️ | ⚠️ | Add `responseShape=html`. |
| `cloud_storage_probe.go` | ➖ | ➖ | Bucket enum. |
| `command_injection_probe.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=cmd-injection`. |
| `cross_domain_policy_probe.go` | ➖ | ➖ | Fixed file. |
| `csrf_probe.go` | ⚠️ | ⚠️ | Add `method`. |
| `dangling_markup.go` | ✅ | ⚠️ | Migrated in this PR as the Phase 3 reference. |
| `deserialization_probe.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=deserialization`. |
| `dns_san_probe.go` | ➖ | ➖ | Certificate metadata. |
| `dom_xss_probe.go` | ⚠️ | ⚠️ | Add `payloadClass=dom-xss`. |
| `file_upload_probe.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=upload-bypass`. |
| `formula_injection.go` | ✅ | ⚠️ | Migrated in this PR as the Phase 3 reference. |
| `http_methods_probe.go` | ⚠️ | ⚠️ | Add `method` from allowed set. |
| `jwt_probe.go` | ⚠️ | ⚠️ | `oracleName=jwt`. |
| `jwt_advanced_probe.go` | ⚠️ | ⚠️ | `oracleName=jwt`. |
| `login_probe.go` | ⚠️ | ⚠️ | Add `param`. |
| `magic_link_invite_probe.go` | ⚠️ | ⚠️ | Add `param=token`. |
| `mfa_probe.go` | ⚠️ | ⚠️ | Add `param=otp`. |
| `oauth_probe.go` | ⚠️ | ⚠️ | Add `param=redirect_uri`|`state`. |
| `oauth_session_probe.go` | ⚠️ | ⚠️ | Cookie-scoped. |
| `password_reset_probe.go` | ⚠️ | ⚠️ | Add `param=token`. |
| `postmessage_probe.go` | ➖ | ➖ | Browser observation. |
| `reverse_tabnabbing_probe.go` | ⚠️ | ⚠️ | Add `responseShape=html`. |
| `saml_probe.go` | ⚠️ | ⚠️ | Add `param=SAMLResponse`. |
| `security_headers_probe.go` | ⚠️ | ⚠️ | `method=GET`. |
| `session_lifecycle_probe.go` | ⚠️ | ⚠️ | Cookie-scoped. |
| `smtp_injection_probe.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=smtp-crlf`. |
| `ssi_injection_probe.go` | ⚠️ | ⚠️ | Add `param`, `payloadClass=ssi`. |
| `tls_config_probe.go` | ➖ | ➖ | Transport metadata. |
| `ui_simulation_probe.go` | ➖ | ➖ | Browser-only. |
| `verbose_error_probe.go` | ⚠️ | ⚠️ | Add `responseShape`. |
| `websocket_probe.go` | ⚠️ | ⚠️ | `oracleName=websocket`. |
| `xssi_jsonp_probe.go` | ⚠️ | ⚠️ | Add `param=callback`. |

## Reference migration

`dangling_markup.go` and `formula_injection.go` are the Phase 3
references. Migration checklist (mirrors the Phase 1 pattern):

1. Ensure `EvidenceFields` includes `method`, `url`, `param`,
   `payloadClass`, and (for HTML-context probes) `reflectionContext` +
   `responseShape`.
2. Stamp `oracleName` with the probe's stable identifier and
   `oracleVersion` with a monotonically bumped version string (start at
   `v1`).
3. Route High/Critical candidates through `SubmitVerifiedFinding` so
   `verifiedBy=<probe>@v1` is stamped automatically. Findings without
   a verifier stamp are eligible for strict-mode suppression.

Normalizer behaviour is idempotent: existing free-form keys survive,
missing fields are inferred where possible, and every finding gains
`evidenceQuality = "valid"|"incomplete"`.

## Appendix — audit one-liner

```sh
grep -L 'payloadClass' backend/internal/scanner/*_probe.go backend/internal/scanner/active_*.go
```
