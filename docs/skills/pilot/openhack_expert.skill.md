# SKILL: openhack_expert

- **Agent:** `openhack_expert`
- **Layer:** triage/review
- **Status:** pilot

## 1) Purpose

Apply OpenHack expert framing to existing findings and enrich them with expert-specific quality analysis.

## 2) Owned decisions

- Select best OpenHack expert per finding.
- Attach expert assessment (decision, rationale, obligations, follow-up probes).
- Use deterministic fallback annotations when AI is unavailable.

## 3) Required inputs

- Existing findings from prior agents.
- OpenHack prompt pack.
- Optional AI client.

## 4) Expected outputs

- Enriched findings (same finding set, additional evidence fields).
- Metadata for expert usage and LLM/fallback counts.

## 5) Hard constraints

- Respect per-run LLM call cap.
- Preserve original findings; annotate in-place semantics only.

## 6) Escalation / handoff

- Hand off enriched findings to `openhack_triage` and other triage/reporting layers.
- Surface evidence gaps for follow-up probing.

## 7) Non-goals (must not do)

- Must not create brand-new findings from scratch.
- Must not suppress findings as final reportability decisions.
