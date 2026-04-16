from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from fastapi import FastAPI
import numpy as np
import onnxruntime as ort
from pydantic import BaseModel, Field


logger = logging.getLogger("ml-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())


class Finding(BaseModel):
    id: str = ""
    category: str = ""
    severity: str = "info"
    title: str = ""
    description: str = ""
    evidence: str = ""
    recommendation: str = ""


class ScoreFindingsRequest(BaseModel):
    findings: List[Finding] = Field(default_factory=list)


class ScoredFinding(BaseModel):
    finding: Finding
    score: float
    confidence: float
    exploitability: str


class ScoreFindingsResponse(BaseModel):
    scoredFindings: List[ScoredFinding]


class AttackPathsRequest(BaseModel):
    findings: List[Finding] = Field(default_factory=list)


class AttackPathsResponse(BaseModel):
    attackPaths: List[str]


class RemediationPlanRequest(BaseModel):
    findings: List[Finding] = Field(default_factory=list)
    limit: int = 5


class RemediationPlanResponse(BaseModel):
    remediationPlan: List[str]


class FalsePositiveCandidatesRequest(BaseModel):
    findings: List[Finding] = Field(default_factory=list)


class FalsePositiveCandidatesResponse(BaseModel):
    candidates: List[ScoredFinding]


class ONNXScorer:
    def __init__(self, model_path: str) -> None:
        self.model_path = model_path
        self.ready = False
        self.error: Optional[str] = None
        self.input_name: Optional[str] = None
        self.output_name: Optional[str] = None
        self.session: Optional[ort.InferenceSession] = None

        if not model_path:
            self.error = "MODEL_PATH not set"
            return

        if not os.path.exists(model_path):
            self.error = f"model not found at {model_path}"
            return

        try:
            providers = ["CPUExecutionProvider"]
            self.session = ort.InferenceSession(model_path, providers=providers)
            self.input_name = self.session.get_inputs()[0].name
            self.output_name = self.session.get_outputs()[0].name
            self.ready = True
            logger.info("Loaded ONNX model: %s", model_path)
        except Exception as exc:
            self.error = str(exc)
            logger.warning("Failed to load ONNX model at %s: %s", model_path, exc)

    def predict(self, findings: List[Finding]) -> Optional[List[float]]:
        if not self.ready or not self.session or not self.input_name or not self.output_name:
            return None

        try:
            features = np.asarray([finding_features(f) for f in findings], dtype=np.float32)
            outputs = self.session.run([self.output_name], {self.input_name: features})
            if not outputs:
                return None
            out = np.asarray(outputs[0])

            if out.ndim == 1:
                values = out.astype(np.float32)
                return [clamp01(float(v)) for v in values.tolist()]

            if out.ndim == 2:
                if out.shape[1] == 1:
                    values = out[:, 0].astype(np.float32)
                    return [clamp01(float(v)) for v in values.tolist()]
                if out.shape[1] >= 2:
                    # Assume binary classifier probabilities/logits and take positive-class column.
                    values = out[:, 1].astype(np.float32)
                    return [clamp01(float(v)) for v in values.tolist()]

            return None
        except Exception as exc:
            logger.warning("ONNX inference failed; using heuristic fallback: %s", exc)
            return None


onnx_scorer = ONNXScorer(os.getenv("MODEL_PATH", "").strip())


app = FastAPI(title="Auto Bughunter ML Service", version="0.1.0")


@app.get("/health")
def health() -> Dict[str, str]:
    if onnx_scorer.ready:
        return {"status": "ok", "mode": "onnx", "modelPath": onnx_scorer.model_path}
    return {"status": "ok", "mode": "heuristic", "reason": onnx_scorer.error or "onnx unavailable"}


@app.post("/v1/score-findings", response_model=ScoreFindingsResponse)
def score_findings(req: ScoreFindingsRequest) -> ScoreFindingsResponse:
    scored = score_findings_internal(req.findings)
    return ScoreFindingsResponse(scoredFindings=scored)


@app.post("/v1/attack-paths", response_model=AttackPathsResponse)
def attack_paths(req: AttackPathsRequest) -> AttackPathsResponse:
    cats = {normalize(f.category) for f in req.findings if normalize(f.category)}
    paths: List[str] = []

    if has_any(cats, "information_disclosure", "reconnaissance", "wordlist") and has_any(cats, "access_control", "api_security"):
        paths.append("Service discovery can expose sensitive endpoints, then weak access control may allow unauthorized data access.")
    if has_any(cats, "input_validation") and has_any(cats, "api_security", "access_control"):
        paths.append("Input validation weaknesses can be chained with API authorization gaps to move from probing to account-level compromise.")
    if has_any(cats, "cors_redirect", "api_security") and has_any(cats, "access_control"):
        paths.append("Permissive CORS or open redirects can assist token/session abuse when access-control checks are weak.")
    if has_any(cats, "headers", "scanning", "tls"):
        paths.append("Transport and header weaknesses can increase exploit reliability for higher-risk application flaws.")

    if not paths:
        paths.append("No high-confidence multi-step attack chain inferred from current findings; focus on top-severity remediations first.")

    return AttackPathsResponse(attackPaths=paths[:3])


@app.post("/v1/remediation-plan", response_model=RemediationPlanResponse)
def remediation_plan(req: RemediationPlanRequest) -> RemediationPlanResponse:
    limit = req.limit if req.limit > 0 else 5
    scored = score_findings_internal(req.findings)

    out: List[str] = []
    seen = set()
    for s in scored:
        rec = compact(s.finding.recommendation)
        if not rec:
            continue
        key = rec.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(f"{rec} (from: {compact(s.finding.title)})")
        if len(out) >= limit:
            break

    if not out:
        out.append("Triage and fix high severity findings first, then medium severity findings with internet exposure.")

    return RemediationPlanResponse(remediationPlan=out)


@app.post("/v1/false-positive-candidates", response_model=FalsePositiveCandidatesResponse)
def false_positive_candidates(req: FalsePositiveCandidatesRequest) -> FalsePositiveCandidatesResponse:
    scored = score_findings_internal(req.findings)
    candidates = [s for s in scored if s.confidence <= 0.55]
    return FalsePositiveCandidatesResponse(candidates=candidates[:5])


def score_findings_internal(findings: List[Finding]) -> List[ScoredFinding]:
    scored: List[ScoredFinding] = []
    model_scores = onnx_scorer.predict(findings) if findings else None

    for idx, f in enumerate(findings):
        text = normalize(f"{f.title} {f.description} {f.evidence}")
        heuristic_score = severity_base(f.severity) + category_weight(f.category)

        for keyword, weight in keyword_weights().items():
            if keyword in text:
                heuristic_score += weight

        heuristic_score = clamp01(heuristic_score)

        if model_scores and idx < len(model_scores):
            # Blend model probability with current deterministic score for stable behavior.
            score = clamp01(0.65 * model_scores[idx] + 0.35 * heuristic_score)
            confidence = clamp01(0.55 + score * 0.40)
        else:
            score = heuristic_score
            confidence = clamp01(0.45 + score * 0.45)

        exploitability = exploitability_from_score(score)

        scored.append(
            ScoredFinding(
                finding=f,
                score=round(score, 2),
                confidence=round(confidence, 2),
                exploitability=exploitability,
            )
        )

    scored.sort(key=lambda x: (-x.score, -x.confidence, x.finding.title.lower()))
    return scored


def severity_base(sev: str) -> float:
    sev = normalize(sev)
    if sev == "high":
        return 0.75
    if sev == "medium":
        return 0.55
    if sev == "low":
        return 0.35
    return 0.2


def category_weight(category: str) -> float:
    category = normalize(category)
    if category in {"access_control", "input_validation", "api_security"}:
        return 0.15
    if category in {"information_disclosure", "cors_redirect"}:
        return 0.08
    return 0.03


def keyword_weights() -> Dict[str, float]:
    return {
        "sql": 0.15,
        "xss": 0.15,
        "idor": 0.2,
        "auth": 0.12,
        "token": 0.1,
        "session": 0.1,
        "admin": 0.1,
        "disclosure": 0.08,
        "graphql": 0.08,
        "credentials": 0.15,
        "injection": 0.15,
        "path traversal": 0.18,
    }


def exploitability_from_score(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def has_any(values: set[str], *targets: str) -> bool:
    for t in targets:
        if t in values:
            return True
    return False


def normalize(value: Optional[str]) -> str:
    return " ".join((value or "").strip().lower().split())


def compact(value: Optional[str]) -> str:
    return " ".join((value or "").strip().split())


def clamp01(value: float) -> float:
    if value < 0:
        return 0
    if value > 1:
        return 1
    return value


def finding_features(f: Finding) -> List[float]:
    text = normalize(f"{f.title} {f.description} {f.evidence}")
    keyword_hit_count = 0.0
    keyword_weight_sum = 0.0
    for kw, wt in keyword_weights().items():
        if kw in text:
            keyword_hit_count += 1.0
            keyword_weight_sum += wt

    title_len = min(len(f.title), 200) / 200.0
    desc_len = min(len(f.description), 600) / 600.0
    rec_len = min(len(f.recommendation), 300) / 300.0

    return [
        severity_base(f.severity),
        category_weight(f.category),
        clamp01(keyword_weight_sum),
        clamp01(keyword_hit_count / 8.0),
        clamp01(title_len),
        clamp01(desc_len),
        clamp01(rec_len),
        1.0,
    ]
