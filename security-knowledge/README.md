# Security Knowledge Service

Curated retrieval-only sidecar for AppSec context enrichment.

## Purpose

This service is intentionally **not** a standalone LLM. It provides:

- curated, short security notes
- source URLs and citations
- deterministic retrieval for findings, attack paths, and remediation planning

The backend remains the single orchestrator and may pass retrieved context into
the configured AI summary flow.

## Endpoints

- `GET /health`
- `POST /v1/retrieve`

## Corpus policy

`data/corpus.json` is generated content. Do not hand-edit it.

The source-of-truth now lives in `sources/corpus_sources.json`. It contains
approved references and short curated notes for the current phase-1 seed set.
The generated corpus keeps the runtime schema stable for
`security-knowledge/app/main.py`, which validates and scores the following
fields:

- `id`
- `title`
- `url`
- `sourceType`
- `license`
- `topic`
- `vulnerabilityClass`
- `technique`
- `keywords`
- `passage`

Only a narrow allowlist of source families is accepted:

- `portswigger`
- `owasp`
- `cwe`

Only `source-url-only` is accepted for `license`.

The policy is unchanged: keep short curated notes with citations to public
references, and avoid mirroring article bodies into the runtime corpus.

## Maintenance flow

1. Update `sources/corpus_sources.json` with approved references and curated
   note metadata.
2. Optionally fetch plain text from those approved websites into a JSON review
   artifact:

   ```bash
   cd security-knowledge
   python3 tools/generate_corpus.py \
     fetch-web-text \
     --sources sources/corpus_sources.json \
     --output data/website_text.json
   ```

   This satisfies the website-ingestion workflow: it reads allowed websites,
   extracts plain text, and writes it into JSON for review or future corpus
   drafting. The runtime corpus still stores only short curated notes.
3. Rebuild the generated corpus and review report:

   ```bash
   cd security-knowledge
   python3 tools/generate_corpus.py \
     build \
     --sources sources/corpus_sources.json \
     --website-text data/website_text.json \
     --output data/corpus.json \
     --review-output data/corpus.review.json
   ```

4. Review `data/corpus.review.json` for exceptions before committing changes.

## Review workflow

The generated review report is intentionally exception-focused. It highlights:

- validation failures such as missing required fields, invalid URLs, duplicate
  IDs, or passages that exceed the configured length bound
- duplicate clusters where two sources would produce near-identical entries for
  the same vulnerability class and technique
- website import failures
- low-confidence website imports, such as unusually short extracted text or
  title mismatches
- style/policy warnings, such as passages that no longer follow the short-note
  convention

## Validation

The repository includes lightweight tests for the generator and schema
compatibility:

```bash
cd security-knowledge
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

## Rollout

- Phase 1: automate generation for the current small curated seed corpus
- Phase 2: expand coverage to additional vulnerability classes once the source,
  review, and regeneration workflow is stable
