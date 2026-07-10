# SKILL: openhack_triage

- **Agent:** `openhack_triage`
- **Layer:** triage/review
- **Status:** pilot

## 1) Purpose

Apply OpenHack finding-triage decisions to candidate findings and enforce reportability outcomes.

## 2) Owned decisions

- Decide accepted/downgraded/rejected/duplicate/needs_context outcomes.
- Apply severity and confidence gating rules from triage output.
- Suppress rejected/duplicate findings from downstream output.

## 3) Required inputs

- Candidate findings from prior stages.
- OpenHack finding-triage prompt.
- Optional AI client.

## 4) Expected outputs

- Kept findings with triage evidence fields.
- Metadata on accepted/rejected/deferred and LLM/fallback counts.

## 5) Hard constraints

- Respect triage call cap.
- Enforce downgrade protection for high-impact findings when proof policy is fully satisfied.

## 6) Escalation / handoff

- Mark `needs_context` findings for manual or later evidence collection.
- Hand accepted/downgraded findings to reporting/remediation.

## 7) Non-goals (must not do)

- Must not run probing or exploitation logic.
- Must not invent evidence that was not present in findings/probe artifacts.
