# SKILL: adaptive_probe

- **Agent:** `adaptive_probe`
- **Layer:** discovery/probing
- **Status:** pilot

## 1) Purpose

Run an evidence-driven one-probe-at-a-time loop that chooses the next highest-value probe from live observations.

## 2) Owned decisions

- Choose next single probe category/endpoint/param/payload via AI.
- Decide when to stop probing before budget is exhausted.
- Prioritize attack-path-guided signals when enabled.

## 3) Required inputs

- Configured `aiClient` and `scanService`.
- Target URL, auth profile, scan options.
- Prior findings/probe history (if available).

## 4) Expected outputs

- Confirmed findings from successful probe steps.
- Step-level metadata (steps, stop reason, WAF/near-miss stats).
- Reasoning-loop events describing each decision.

## 5) Hard constraints

- Respect configured step budget.
- Stop on invalid AI decisions or cancellation.
- Respect scan policy pack and suppression advisories.

## 6) Escalation / handoff

- Hand off confirmed findings to triage/review layers.
- Emit enough probe history for reflection-oriented agents to continue.

## 7) Non-goals (must not do)

- Must not execute multi-step exploit-chain synthesis.
- Must not perform final severity triage/report gating.
