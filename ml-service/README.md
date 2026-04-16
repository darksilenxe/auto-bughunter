# ML Service (Option 1)

Inference-only ML microservice for Auto Bughunter.

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
uvicorn app.main:app --host 0.0.0.0 --port 8090
```
