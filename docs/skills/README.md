# Agent SKILL Files

This directory is the source of truth for agent responsibility boundaries in this repository.

## Objective

Make agent behavior explicit, auditable, and easier to evolve.

## Scope

Phase A focuses on backend registered agents in `/home/runner/work/auto-bughunter/auto-bughunter/backend/internal/agent/factory.go`.
Later phases extend to sidecars and OpenHack flow alignment.

## SKILL schema

All SKILL files use the schema in [`SKILL_SPEC.md`](./SKILL_SPEC.md):

- Purpose
- Owned decisions
- Required inputs
- Expected outputs
- Hard constraints
- Escalation / handoff
- Non-goals (must-not-do boundaries)

## Ownership layers

Each SKILL should declare one primary ownership layer:

- Discovery / probing
- Correlation / chain reasoning
- Triage / review
- Reporting / remediation
- Tool / command generation

## Pilot (Phase A)

Pilot SKILL files are in [`pilot/`](./pilot):

- `adaptive_probe`
- `cve_reverse_engineer`
- `openhack_expert`
- `openhack_triage`
- `pentest_loop`
- `reasoning_iteration`
- `dynamic_commands`

## Governance and change control

- Any new agent registration or major agent behavior change must update the corresponding SKILL file in the same PR.
- If an agent has no SKILL file, add one before merging behavior changes.
- Reviewers should check for:
  - boundary conflicts with other agents,
  - missing hard constraints,
  - stale handoff rules,
  - mismatches with runtime behavior in `/home/runner/work/auto-bughunter/auto-bughunter/backend/internal/agent`.

## Rollout

- **Phase A (now):** pilot set above.
- **Phase B:** remaining backend agents.
- **Phase C:** enforce "no agent change without SKILL update" and run periodic drift audits.
