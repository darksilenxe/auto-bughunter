# SKILL: fp_correction

- **Agent:** `scanning` (scanner pipeline layer)
- **Layer:** triage/review
- **Status:** pilot

## 1) Purpose

Detect false positives inline during the scan's pre-report verification pipeline
and automatically suppress or adjust candidate findings without operator
intervention. Feeds confirmed false-positive records back to the ML calibration
pipeline so accuracy improves over successive scans.

## 2) Owned decisions

- Track every probe firing and suppression outcome in a per-scan `FPSignalStore`.
- Apply a rule-based FP-rate estimator to classify findings as likely-real,
  borderline, or likely-FP based on the suppressed/fired ratio.
- For borderline findings (FP rate 30–70% with ≥ 5 samples), call the AI
  classifier (`ai.Client.ClassifyFalsePositive`) on the fast model lane.
- Suppress a candidate finding when the estimator or AI classifier identifies
  it as a false positive, stamping the outcome with `fpCorrection.reason` and
  `fpCorrection.hint` in `EvidenceFields`.
- Feed confirmed AI-classified FP records to `ml.Service.CalibrateProbeSignals`
  at scan end.

## 3) Required inputs

- `ScanOptions.UseAIFPCorrection = true` (opt-in; default off).
- Optional `scanner.FPClassifierClient` (satisfied by `*ai.Client`). When nil,
  only the rule-based estimator runs; borderline findings are admitted.
- Optional `scanner.ProbeCalibratorService` (satisfied by `*ml.Service`). When
  nil, the cross-scan ML calibration step is skipped.
- The request context produced by `scanner.Run` must carry the `ProbeCorrection`
  via `WithProbeCorrection`.

## 4) Expected outputs

- Suppressed findings are removed from the scan's emitted finding set.
- `VerificationOutcome.Reason` is set to `"fp-rate-above-threshold"` or
  `"ai-fp-classification"` for FP-corrected findings.
- `VerificationOutcome.CorrectionHint` carries a human-readable explanation.
- `model.ProbeRecord` entries for AI-confirmed FP corrections accumulate in
  `ProbeCorrection.correctedRecords` and are drained at scan end for ML
  calibration.
- `EvidenceFields["fpCorrection.reason"]` and `["fpCorrection.hint"]` are
  stamped on the suppressed finding snapshot (visible in audit logs).

## 5) Hard constraints

- Must not suppress findings that are already suppressed by proof-policy or PoC
  replay failure (the store still records them, but no second suppression is
  applied).
- Must not make AI calls for findings in the LikelyFP category (≥ 70% FP rate);
  deterministic suppression is applied without a model call.
- Must not make AI calls for findings in the LikelyReal category (< 30% FP
  rate) or when fewer than 5 samples have been collected.
- Must not call the AI classifier when `FPClassifier` is nil.
- Must not suppress any finding when `UseAIFPCorrection` is false.

## 6) Escalation / handoff

- Suppressed findings remain in scanner memory for audit; they are never
  permanently deleted.
- The `false_positive_review` agent (ML layer) continues to run independently
  and may identify further FP candidates from the post-scan finding set.
- Corrected probe records are passed to `ml.Service.CalibrateProbeSignals` to
  update the per-category confidence multipliers for future scans.

## 7) Non-goals (must not do)

- Must not re-evaluate findings already verified by PoC replay.
- Must not apply corrections cross-scan (each `FPSignalStore` is per-scan only).
- Must not modify the severity of an admitted finding (correction is
  suppress-or-admit only).
- Must not disable or bypass the existing proof-policy or differential
  verification layers.
