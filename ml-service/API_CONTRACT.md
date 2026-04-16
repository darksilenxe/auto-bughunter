# API Contract

## POST /v1/score-findings

Request:

```json
{
  "findings": [
    {
      "id": "finding-1",
      "category": "input_validation",
      "severity": "high",
      "title": "Potential SQL injection",
      "description": "...",
      "evidence": "...",
      "recommendation": "Use parameterized queries"
    }
  ]
}
```

Response:

```json
{
  "scoredFindings": [
    {
      "finding": {"id": "finding-1", "category": "input_validation", "severity": "high", "title": "...", "description": "...", "evidence": "...", "recommendation": "..."},
      "score": 0.92,
      "confidence": 0.86,
      "exploitability": "high"
    }
  ]
}
```

## POST /v1/attack-paths

Request:

```json
{
  "findings": []
}
```

Response:

```json
{
  "attackPaths": ["..."]
}
```

## POST /v1/remediation-plan

Request:

```json
{
  "findings": [],
  "limit": 5
}
```

Response:

```json
{
  "remediationPlan": ["..."]
}
```

## POST /v1/false-positive-candidates

Request:

```json
{
  "findings": []
}
```

Response:

```json
{
  "candidates": [
    {
      "finding": {"id": "...", "category": "...", "severity": "...", "title": "...", "description": "...", "evidence": "...", "recommendation": "..."},
      "score": 0.41,
      "confidence": 0.55,
      "exploitability": "low"
    }
  ]
}
```
