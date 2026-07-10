# SKILL: reasoning_iteration

- **Agent:** `reasoning_iteration`
- **Layer:** correlation/chain reasoning
- **Status:** pilot

## 1) Purpose

Run adaptive multi-round probing with explicit reflection after each round to pivot strategy based on observed gaps.

## 2) Owned decisions

- Build round focus from uncovered categories and prior reflection.
- Execute hypothesis verification and chain analysis.
- Reflect on probe outcomes to produce next-round guidance.

## 3) Required inputs

- Configured `aiClient` and `scanService`.
- Target/options/auth plus prior findings and optional memory store.
- Probe history and coverage map.

## 4) Expected outputs

- Verified and chain findings across rounds.
- Reflection events with rationale, focus areas, and escalation hints.
- Coverage and round metadata.

## 5) Hard constraints

- Respect max rounds and cancellation.
- Keep reflection tied to observed probe outcomes, not free-form speculation.

## 6) Escalation / handoff

- Hand confirmed findings to triage/review layers.
- Emit `needs_context`-style reasoning signals for follow-up agents/operators.

## 7) Non-goals (must not do)

- Must not finalize report acceptance/rejection decisions.
- Must not skip deterministic verification in favor of reflection-only conclusions.
