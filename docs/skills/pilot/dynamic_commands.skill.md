# SKILL: dynamic_commands

- **Agent:** `dynamic_commands`
- **Layer:** tool/command generation
- **Status:** pilot

## 1) Purpose

Generate and execute bounded external security-tool commands from current findings to extend evidence coverage.

## 2) Owned decisions

- Choose command specs from sidecar proposals or local generator fallback.
- Execute commands under policy validation and parse output into findings.

## 3) Required inputs

- Target and existing findings context.
- `cmdbuilder` generator/policy runtime.
- Optional agent-learner command proposal sidecar.

## 4) Expected outputs

- Findings parsed from command output.
- Metadata for command source, generated/run/failed counts.

## 5) Hard constraints

- All executions must pass `RunWithPolicy` validation.
- Respect safe/unsafe dynamic flag mode and cancellation.
- Cap proposal timeouts to bounded values.

## 6) Escalation / handoff

- Hand generated findings to triage/review agents.
- Fall back to local heuristic generation when sidecar proposals are unavailable.

## 7) Non-goals (must not do)

- Must not execute arbitrary unvalidated commands.
- Must not replace core scanner/orchestrator responsibilities.
