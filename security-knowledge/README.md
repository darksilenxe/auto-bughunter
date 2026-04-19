# Security Knowledge Service

Curated retrieval-only sidecar for AppSec context enrichment.

## Purpose

This service is intentionally **not** a standalone LLM. It provides:

- curated, manually-authored security notes
- source URLs and citations
- deterministic retrieval for findings, attack paths, and remediation planning

The backend remains the single orchestrator and may pass retrieved context into
the configured AI summary flow.

## Endpoints

- `GET /health`
- `POST /v1/retrieve`

## Corpus policy

The seed corpus in `data/corpus.json` contains short, manually-authored notes
with citations to public security references such as PortSwigger, OWASP, and
CWE. It is designed to avoid mirroring third-party article bodies while still
providing useful context and traceable source URLs.
