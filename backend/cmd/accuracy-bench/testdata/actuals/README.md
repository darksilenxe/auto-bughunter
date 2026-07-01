# Sample scan actuals

The `accuracy-bench` CLI grades the manifests in `../corpus/` against
`ActualScan` JSON files in this directory. Each file is one scan of one
target, keyed by the target name.

The two fixtures checked in here are intentionally minimal:

- `clean-json-api.json` — an empty scan of the clean-JSON-API control.
  Anchors the workflow: precision/recall are undefined (no findings, no
  expected), and any drift into false positives against this baseline
  will fail CI.
- `juice-shop.json` — a hand-crafted "expected best-case" scan of OWASP
  Juice Shop. Every expected finding is present; no false positives.
  Serves as a smoke test for the grading pipeline until real scans are
  wired into the nightly workflow (Phase 0 follow-up).

**Do not** treat these as claims about current scanner accuracy. They exist
so the nightly workflow runs green today. Real per-run actuals should be
produced by the nightly job once vulnerable targets are deployed and the
scanner is pointed at them.
