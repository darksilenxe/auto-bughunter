# Contributing to Auto BugHunter

Thanks for considering a contribution. This project is split into three
deployable pieces:

| Path        | Stack                              | Purpose                              |
| ----------- | ---------------------------------- | ------------------------------------ |
| `backend/`  | Go 1.25 (`net/http` + `database/sql`) | Scan orchestration, REST API, SARIF/PDF export |
| `frontend/` | React 18 + Vite                    | Operator UI                          |
| `ml-service/` | Python                            | Optional agent-learner sidecar       |

## Getting set up

```bash
# Backend
cd backend
go mod download
go test ./...

# Frontend
cd frontend
npm install
npm run build
```

A full local stack (backend, Postgres, frontend) is available via
`docker-compose up`.

## Development workflow

1. Open an issue for non-trivial changes so design can be discussed first.
2. Branch from `main` and keep PRs focused and small. One logical change per PR.
3. Match the coding style of the surrounding code. The backend uses
   standard library idioms — avoid pulling in new dependencies unless they
   replace meaningful hand-rolled code.
4. Add tests for any new HTTP handler, middleware, or scanner stage. The
   existing tests in `backend/internal/api/*_test.go` are good models.
5. Update the OpenAPI document at `backend/internal/api/openapi.go` when
   you add or change a public endpoint.
6. Update the API Explorer (`frontend/src/pages/ApiExplorer.jsx`) when you
   add a new public endpoint so it is discoverable from the UI.

## Required checks

These commands must pass before requesting review. CI runs them on every
PR (`.github/workflows/ci.yml`):

```bash
# Backend
cd backend
go vet ./...
go build ./...
go test -race ./...

# Frontend
cd frontend
npm install
npm run build
npm test
```

Or, from the repo root:

```bash
make test    # backend (race) + frontend (vitest)
make build   # backend + frontend production build
make lint    # go vet + golangci-lint (if installed)
```

If you have `golangci-lint` installed locally:

```bash
cd backend && golangci-lint run ./...
```

CodeQL runs on every PR via `.github/workflows/codeql.yml`; address any
new alerts it produces.

## Security & responsible scanning

This project actively probes external systems. When adding a scanner stage:

- Always route outbound requests through `internal/safety.ValidateOutboundURL`.
- Respect the per-target concurrency and rate-limit settings.
- Do not add destructive payloads behind anything other than the
  `ALLOW_DESTRUCTIVE_CHECKS` flag.
- Never log or persist credentials supplied via `authProfile`.

If you discover a security vulnerability in this project, please report
it privately rather than filing a public issue.

## Commit messages & PRs

- Use concise, imperative commit subjects (e.g. `add sarif export endpoint`).
- Reference issues in the PR body, not the subject line.
- Mark PRs as **Draft** while still iterating; flip to ready when CI is green.

## Code of conduct

Be kind, be specific, and assume good intent. We'll all get further that way.
