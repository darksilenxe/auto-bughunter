# Accuracy benchmark corpus

Each `*.json` file in this directory is a benchmark **manifest** that describes
the ground truth for one target. The `accuracy-bench` CLI grades an actual scan
against the manifest and emits precision / recall / F1 per category so that
probe changes can be measured objectively.

## Corpus layout

- `juice-shop.json`, `dvwa.json`, `webgoat.json`, `bwapp.json` — classic
  training targets covering injection, XSS, path traversal, command injection.
- `crapi.json`, `vampi.json` — API-first targets covering the API Top-10
  (BOLA, mass assignment, excessive data exposure).
- `clean-spa.json`, `clean-json-api.json` — **negative controls** with no
  known vulnerabilities. They anchor the false-positive rate; any finding on
  a `safeEndpoints` entry is counted as an FP.

Manifests intentionally do **not** hard-code exact evidence strings — matching
uses `(normalized category, normalized path[, parameter, minimum severity])`
so the harness stays stable as evidence phrasing changes.

## Adding a new target

1. Deploy the target somewhere reachable from the scanner (Docker Compose,
   a persistent staging URL, etc.).
2. Run a full scan and copy the resulting findings into
   `../actuals/<target>.json` using the `ActualScan` schema.
3. Author a manifest here. Prefer under-specifying `parameter` and
   `minSeverity` initially; tighten them once the scanner reliably detects
   the finding.
4. Regenerate the baseline: `accuracy-bench -corpus ... -actuals ...
   -output-json /tmp/baseline.json` and commit the JSON as the new baseline.

## What counts as what

| Situation | Category |
|---|---|
| Manifest expects it, scanner reports it (same category, endpoint, param, minSeverity) | **true positive** |
| Manifest expects it, scanner does not report it | **false negative** |
| Scanner reports a finding on a `safeEndpoints` entry | **false positive** |
| Scanner reports an unexpected finding in a category that also has expected entries | **false positive** |
| Scanner reports a finding in a category with no expected entries and no matching `safeEndpoints` | **out of scope** (ignored — adding a new probe must not retroactively regress every target) |
| Category listed in `allowedExtraCategories` | **ignored** for precision |
