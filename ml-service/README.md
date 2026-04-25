# ML Service (Option 1)

Inference + offline training microservice for Auto Bughunter.

## Endpoints

- `GET /health`
- `POST /v1/score-findings`
- `POST /v1/attack-paths`
- `POST /v1/remediation-plan`
- `POST /v1/false-positive-candidates`

## Contract Summary

Request finding shape:

```json
{
  "id": "string",
  "category": "string",
  "severity": "info|low|medium|high",
  "title": "string",
  "description": "string",
  "evidence": "string",
  "recommendation": "string"
}
```

This initial implementation uses deterministic heuristics and is ready to host ONNX model logic behind the same contract.

## ONNX Mode

Set `MODEL_PATH` to an ONNX file path to enable model-backed scoring.

- If model load/inference succeeds, `/v1/score-findings` blends model probabilities with heuristic scores.
- If model load/inference fails, service automatically falls back to heuristic scoring.
- `/health` reports `mode=onnx` when active, otherwise `mode=heuristic` with a reason.
- `ML_SCORING_MODE` controls runtime inference safety behavior:
  - `blend` (default): blend ONNX + heuristic scores
  - `shadow`: return deterministic heuristic scores and log model-vs-heuristic deltas for audit
  - `heuristic`: force deterministic scoring even if ONNX is loaded

Expected model I/O (minimal):

- Input: float32 tensor shaped `[N, 8]`
- Output: one of:
  - `[N]` probabilities
  - `[N,1]` probabilities
  - `[N,2+]` class scores/probabilities (column 1 treated as positive class)

## Local Run

```bash
pip install -r requirements.txt
export MODEL_PATH=/models/risk.onnx
export ML_SCORING_MODE=blend
uvicorn app.main:app --host 0.0.0.0 --port 8090
```

## Training Pipeline

Use the built-in offline pipeline to fetch sanitized engagement data from
`GET /api/ml/engagements`, run data-quality/privacy gates, train/evaluate a
logistic model, package ONNX artifacts, and apply promotion rules.

The dataset includes findings generated from supplemental in-scope resource
scanning (for example normalized text extracted from fetched website resources),
so those signals can contribute to model training.

```bash
pip install -r requirements.txt
python app/training_pipeline.py \
  --api-base http://localhost:8080 \
  --api-key "$BOOTSTRAP_ADMIN_API_KEY" \
  --limit 500 \
  --output-dir /tmp/auto-bughunter-training \
  --models-dir /tmp/auto-bughunter-models \
  --allow-quality-warnings
```

Artifacts per run:

- `engagements.dataset.json` (versioned snapshot)
- `quality_report.json` (record completeness, class-balance, redaction gates)
- `metrics.json` (model vs deterministic baseline)
- `risk-candidate.onnx` (candidate model)
- `manifest.json` (lineage metadata)

Model registry:

- Writes/updates `<models-dir>/registry.json`
- Promotes to `<models-dir>/risk.onnx` only when promotion thresholds are met
