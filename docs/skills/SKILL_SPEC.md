# SKILL File Specification

Use this structure for each agent SKILL file.

## Header

- `Agent`: registered agent name
- `Layer`: one of discovery/probing, correlation/chain reasoning, triage/review, reporting/remediation, tool/command generation
- `Status`: pilot or active

## 1) Purpose

Short statement of why the agent exists.

## 2) Owned decisions

List the decisions this agent is expected to make.

## 3) Required inputs

List required context/dependencies to run correctly.

## 4) Expected outputs

Describe findings, metadata, and event side effects expected from this agent.

## 5) Hard constraints

Non-negotiable safety, scope, or budget limits.

## 6) Escalation / handoff

When this agent should defer, annotate, or hand off to another agent/layer.

## 7) Non-goals (must not do)

Explicitly list responsibilities this agent does not own.

## Authoring rules

- Keep files short and operational.
- Prefer repository terms from code and docs over generic language.
- Include at least one explicit “must not” boundary.
- Update SKILL and implementation together when behavior changes.
