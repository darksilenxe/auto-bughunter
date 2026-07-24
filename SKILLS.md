# SKILLS.md — Working Expectations for the Agent

This file describes how the coding agent should work in this repository based on
the user's repeated expectations.

Read this file together with `/home/runner/work/auto-bughunter/auto-bughunter/AGENTS.md`
before making changes.

---

## 1. Classify the request first

Before acting, decide whether the request is primarily:

- a **code change**
- an **explanation**
- a **plan**
- an **analysis**

Use that classification to choose the workflow.

---

## 2. If the user is asking a question

- Answer directly.
- Do **not** assume the user wants code changes.
- Keep the response concise and specific to the question.

Examples:

- “How does X work?” → explain it.
- “Where is X implemented?” → point to the exact files.
- “Describe the repo structure.” → summarize the structure.

---

## 3. If the user wants a plan or approach

- Gather context first using repository reads/searches.
- Prefer `view`, `rg`, and `glob` for planning work.
- Return the final plan in `<plan>...</plan>` tags.
- Describe **what** should be done, not sample code, unless the user asks for code.
- Do **not** create markdown planning files unless the user explicitly asks for one.

Examples:

- “Create a plan for X” → respond in `<plan>` tags.
- “How would you add X?” → respond in `<plan>` tags.
- “What would you change to support Y?” → respond in `<plan>` tags.

---

## 4. If the task requires code changes

### 4.1 Understand before editing

- Fully understand the request before changing files.
- Read the relevant files and nearby code paths first.
- Understand the build, lint, and test commands for the affected area.

### 4.2 Change scope

- Make the smallest change that completely solves the task.
- Prefer precise, surgical edits over broad refactors.
- Do not fix unrelated issues.
- If a directly related bug is exposed by the requested change, fix it too.

### 4.3 Progress reporting

- Call progress reporting **before the first edit** with a checklist plan.
- Report progress again after meaningful milestones.
- If the task includes file edits, keep the checklist current.

### 4.4 Validation

- Run only the existing validation already used by the repository.
- If `backend/` changes, use the Go validation commands documented in `AGENTS.md`.
- If `frontend/` changes, use `npm ci` and `npm run build`.
- If the change is documentation-only, build/test is usually unnecessary unless docs-specific checks exist.

### 4.5 Documentation

- Update documentation when it is directly affected by the change.
- Do not create extra markdown files unless the user asked for them by name or path.

---

## 5. Response style

- Be concise and direct.
- Prefer short answers over long narration.
- Do not explain every tool call.
- When blocked, clearly state the blocker and what is needed.

---

## 6. Repository-specific expectations

### 6.1 Paths

- Always use absolute repository paths when referring to files.
- The repository root is:
  `/home/runner/work/auto-bughunter/auto-bughunter`

### 6.2 Backend

- Backend code is in `/home/runner/work/auto-bughunter/auto-bughunter/backend`.
- It is a Go module: `auto-bughunter/backend`.
- New agent behavior changes should stay aligned with
  `/home/runner/work/auto-bughunter/auto-bughunter/docs/skills/`.

### 6.3 Frontend

- Frontend code is in `/home/runner/work/auto-bughunter/auto-bughunter/frontend`.
- It is React + Vite in JavaScript.

### 6.4 Python services

- Service contracts must stay stable unless both sides are updated together.

---

## 7. Safety and security rules

- Do not introduce secrets into the repository.
- Run secret scanning before finalizing file edits.
- Run CodeQL review before finishing code-change tasks.
- Do not bypass scope enforcement.
- Do not bypass outbound URL safety checks without a strong, explicit reason.
- Do not enable destructive checks unconditionally.

For this repository in particular:

- Every probe must respect scope.
- Public outbound integrations should continue to respect `secureurl` rules.
- Destructive checks must remain gated by scan options and environment flags.

---

## 8. CI and validation expectations

If the task touches `backend/` or `frontend/`, remember that
`/home/runner/work/auto-bughunter/auto-bughunter/.github/workflows/qa.yml`
is the main PR quality gate.

That workflow includes:

- backend: `go vet`, `go build`, `go test`
- backend accuracy benchmark gate
- backend replay planner regression gate
- frontend: `npm ci`, `npm run build`

Do not add new linting or testing tools unless the task truly requires it.

---

## 9. What not to do

- Do not assume every request needs implementation.
- Do not create plans incrementally in multiple replies when one complete plan is possible.
- Do not create markdown notes, scratchpads, or plan files unless asked.
- Do not make unrelated cleanup edits.
- Do not remove unrelated tests.
- Do not bypass existing safety constraints for convenience.

---

## 10. Preferred working pattern

1. Classify the task.
2. Read the relevant files.
3. If planning, return a complete `<plan>`.
4. If implementing, report progress first.
5. Make minimal edits.
6. Validate the changed area.
7. Run secret scanning and CodeQL for code-change tasks.
8. Respond with a concise summary of what changed.

---

## 11. Intent of this file

This file is not a product feature specification.
It is an operator-expectation guide for the coding agent.

When there is tension between broad creativity and the user's stated workflow,
prefer the user's workflow.
