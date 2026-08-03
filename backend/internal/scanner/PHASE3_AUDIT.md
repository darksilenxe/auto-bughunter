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
through `active_ssti.go`) migrated to `schema` ✅ on 2026-07-04. Batch 2
(next 10 ⚠️ rows: `active_xpath_injection.go` through
`http_methods_probe.go`) migrated to `schema` ✅ on 2026-07-07. Batch 3
(final 17 ⚠️ rows: `jwt_probe.go` through `xssi_jsonp_probe.go`) migrated
to `schema` ✅ on 2026-07-07, completing the Phase 3 evidence-schema
audit — every applicable probe file now emits a Phase 3-compliant
EvidenceRecord (✅) or is marked not-applicable (➖). The first 20 table
rows (all ✅ schema probes through `dangling_markup.go` plus `deserialization_probe.go`
and `file_upload_probe.go`) have been stamped on 2026-08-03: `stamp` column
updated to ✅ for all 17 applicable rows in the first 20. Remaining rows
still carry ⚠️ in the `stamp` column as follow-up work.

| Probe file | schema | stamp | Notes |
| --- | :---: | :---: | --- |
| `active_cors.go` | ✅ | ✅ | Migrated: `payloadClass=cors-origin-reflection`, `url`, `oracleName` added. |
| `active_graphql_introspection.go` | ✅ | ✅ | Migrated: `payloadClass=graphql-introspection`, `oracleName` added. |
| `active_ldap_injection.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=ldap-injection` added. |
| `active_nosqli.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=nosql-operator` added. |
| `active_open_redirect.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=open-redirect` added. |
| `active_path_traversal.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=path-traversal` added. |
| `active_prompt_injection.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=prompt-injection` added. |
| `active_prototype_pollution.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=proto-pollution` added. |
| `active_sqli.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=sqli-error` added. |
| `active_ssti.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=ssti` added. |
| `active_xpath_injection.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=xpath-injection` added. |
| `active_xss.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=xss-reflected`, `reflectionContext` added. |
| `active_xxe.go` | ✅ | ✅ | Migrated: `payloadClass=xxe`, `responseShape=xml` added. |
| `browser_storage_probe.go` | ➖ | ➖ | Browser observation. |
| `clickjacking_probe.go` | ✅ | ✅ | Migrated: `responseShape=html` added. |
| `cloud_storage_probe.go` | ➖ | ➖ | Bucket enum. |
| `command_injection_probe.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=cmd-injection` added. |
| `cross_domain_policy_probe.go` | ➖ | ➖ | Fixed file. |
| `csrf_probe.go` | ✅ | ✅ | Migrated: `method` added. |
| `dangling_markup.go` | ✅ | ✅ | Migrated in this PR as the Phase 3 reference. |
| `deserialization_probe.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=deserialization` added. |
| `dns_san_probe.go` | ➖ | ➖ | Certificate metadata. |
| `dom_xss_probe.go` | ✅ | ⚠️ | Migrated: `payloadClass=dom-xss` added. |
| `file_upload_probe.go` | ✅ | ✅ | Migrated: `param`, `payloadClass=upload-bypass` added. |
| `formula_injection.go` | ✅ | ⚠️ | Migrated in this PR as the Phase 3 reference. |
| `http_methods_probe.go` | ✅ | ⚠️ | Migrated: `method` added from allowed/overridden verb set. |
| `jwt_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=jwt_probe` added. |
| `jwt_advanced_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=jwt_advanced_probe` added via `jwtAdvancedFinding`. |
| `login_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=login_probe` added. |
| `magic_link_invite_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param=token`, `oracleName=magic_link_invite_probe` added. |
| `mfa_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=mfa_probe` added. |
| `oauth_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param=redirect_uri`\|`state`\|`code_challenge`, `payloadClass`, `oracleName=oauth_probe` added. |
| `oauth_session_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=oauth_session_probe` added. |
| `password_reset_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param=token`, `oracleName=password_reset_probe` added. |
| `postmessage_probe.go` | ➖ | ➖ | Browser observation. |
| `reverse_tabnabbing_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `responseShape=html`, `oracleName=reverse_tabnabbing_probe` added. |
| `saml_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param=SAMLResponse`, `oracleName=saml_probe` added. |
| `security_headers_probe.go` | ✅ | ⚠️ | Migrated: `method=GET`, `url`, `oracleName=security_headers_probe` added. |
| `session_lifecycle_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=session_lifecycle_probe` added. |
| `smtp_injection_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param`, `payloadClass=smtp-crlf`, `oracleName=smtp_injection_probe` added. |
| `ssi_injection_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `payloadClass=ssi-injection`, `oracleName=ssi_injection_probe` added (had `param` already). |
| `tls_config_probe.go` | ➖ | ➖ | Transport metadata. |
| `ui_simulation_probe.go` | ➖ | ➖ | Browser-only. |
| `verbose_error_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param`, `responseShape` (already present), `oracleName=verbose_error_probe` added. |
| `websocket_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `oracleName=websocket_probe` added. |
| `xssi_jsonp_probe.go` | ✅ | ⚠️ | Migrated: `method`, `url`, `param=callback`, `oracleName=xssi_jsonp_probe` added. |

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
