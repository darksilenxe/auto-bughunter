# SKILL: post_scan_validator

- **Agent:** `post_scan_validator`
- **Layer:** triage/review
- **Status:** pilot

## 1) Purpose

Run a two-pass post-scan re-evaluation after the deterministic scan completes to
improve finding accuracy by reducing false positives and surfacing false negatives.

## 2) Owned decisions

- **Pass A (FP Re-Test):** Select low-confidence or weak-evidence findings
  (`Confidence < 0.65` or `EvidenceQualityTier` in `low/speculative/unconfirmed`)
  and re-probe each one via the scanner's deterministic oracle.  Annotate the
  copy with `retestResult=confirmed` (confidence raised to ≥ 0.80) or
  `retestResult=not-confirmed` (confidence reduced by 0.20, floor 0.10).
- **Pass B (FN Gap Sweep):** Prefer the latest Phase 2 `SurfaceGap` snapshot
  (`DetectSurfaceGaps` / `SelectHighROIGaps`) over simple “no finding on this
  URL” heuristics.  Probe the top 20 gap-derived targets, carrying through
  missing-parameter context when present, with a lightweight deterministic
  category sweep (`xss`, `cors`, `open_redirect`, `sqli`, `ldap`, `xpath`,
  `formula_injection`, `prototype_pollution`, `clickjacking`,
  `command_injection`, `ssi_injection`, `smtp_injection`).  When no gap
  snapshot is available, fall back to the old uncovered-seed-endpoint sweep.
- When an `aiClient` is configured, generate and verify AI hypotheses for the
  un-covered surface alongside the deterministic sweep.

## 3) Required inputs

- `ScanOptions.UsePostScanValidation = true` (gate flag; defaults to false).
- A configured `scanService` (`*scanner.Service`); agent is a no-op without it.
- `AllFindings` populated with the full post-scan finding set.
- `Target` and `Options.SeedRuntimeEndpoints` for the Pass B fallback surface.
- The latest Phase 2 surface-gap snapshot when available.
- `Scope` for in-scope validation before every active probe.

## 4) Expected outputs

- Annotated copies of re-tested findings (Pass A) with `EvidenceFields["retestResult"]`
  set to `"confirmed"` or `"not-confirmed"` and adjusted `Confidence`.
- New findings tagged with `Sources: ["post_scan_validator", "fn_sweep"]` (Pass B).
- Metadata keys: `fp_retest_total`, `fp_retest_confirmed`, `fp_retest_unconfirmed`, `fn_sweep_new`.
- `ScanEventInfo` events at start, Pass A/B milestones, and completion.

## 5) Hard constraints

- Must check `scope.IsURLInScope` before every active probe call.
- Must skip Pass A (active re-probes) when `Options.PassiveOnly` is true.
- Must skip Pass B (active gap sweep) when `Options.PassiveOnly` is true.
- Must check `ctx.Done()` between iterations and exit cleanly on cancellation.
- Must not delete findings; the human triage board has final say.
- Pass B endpoint budget is capped at 20 endpoints regardless of surface size.

## 6) Escalation / handoff

- Re-tested findings should be consumed by the triage board and `false_positive_review`
  agent in subsequent rounds.
- New Pass B findings feed into the `analysis` and `reporting` layers.
- Findings confirmed by Pass A with `ProofState < validated` should be escalated
  to `impact_verifier`.

## 7) Non-goals (must not do)

- Must not perform final triage policy decisions (that is owned by `false_positive_review`).
- Must not bypass scanner verification with AI-only claims (all confirmations go
  through `RunHypothesisVerification`).
- Must not run the full `scanner.Run()` pipeline; only targeted oracle calls are allowed.
- Must not modify `AllFindings` in place; only emit annotated copies.
