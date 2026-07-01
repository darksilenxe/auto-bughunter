from __future__ import annotations

import hmac
import logging
import os
from typing import Dict, List, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import numpy as np
import onnxruntime as ort
from pydantic import BaseModel, Field

# Lazy imports for calibration (scipy/sklearn) — only loaded when the
# calibration endpoint is actually exercised so a missing install degrades
# gracefully to an empty-multiplier response rather than crashing the service.
try:
    from scipy.stats import beta as scipy_beta  # type: ignore
    from sklearn.ensemble import GradientBoostingClassifier  # type: ignore
    _CALIBRATION_DEPS_OK = True
except ImportError:
    _CALIBRATION_DEPS_OK = False


logger = logging.getLogger("ml-service")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())

# Optional shared-secret auth between the backend and this sidecar. When set,
# every request other than /health must present `Authorization: Bearer <token>`.
SIDECAR_AUTH_TOKEN = os.getenv("SIDECAR_AUTH_TOKEN", "").strip()
_AUTH_EXEMPT_PATHS = {"/health"}
SCORING_MODE = os.getenv("ML_SCORING_MODE", "blend").strip().lower()
# When ML_CALIBRATE_PROBE_SIGNALS=true the /v1/calibrate-probe-signals endpoint
# returns non-trivial per-category multipliers instead of the default 1.0 stubs.
_CALIBRATE_ENABLED = os.getenv("ML_CALIBRATE_PROBE_SIGNALS", "false").strip().lower() == "true"


def _extract_bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header:
        return ""
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


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


# ---------------------------------------------------------------------------
# Probe-signal calibration models
# ---------------------------------------------------------------------------

class ProbeRecordInput(BaseModel):
    """Slim projection of model.ProbeRecord sent from Go for calibration."""
    category: str = ""
    outcome: str = ""  # confirmed | waf_blocked | near_miss | server_error | no_signal | error
    statusCode: int = 0
    endpoint: str = ""
    # Phase 4 optional evidence-quality signals (backward-compatible:
    # older Go clients simply don't set these). They influence the
    # Bayesian prior — evidence-valid records nudge the posterior
    # toward the observed outcome; incomplete-evidence records are
    # weighted less confidently.
    evidenceValid: bool = False
    differentialConfirmed: bool = False
    surfaceGapReason: str = ""
    oracleName: str = ""
    oracleVersion: str = ""

    class Config:
        extra = "allow"  # tolerate any future field additions


class CalibrateProbeSignalsRequest(BaseModel):
    probeRecords: List[ProbeRecordInput] = Field(default_factory=list)


class CategoryCalibration(BaseModel):
    """Per-category calibration result."""
    category: str
    # Bayesian posterior mean of the no-signal rate (Beta distribution).
    noSignalRate: float
    # Lower bound of the 95% credible interval on the no-signal rate.
    noSignalRateLower: float
    # Upper bound of the 95% credible interval on the no-signal rate.
    noSignalRateUpper: float
    # Calibrated confidence multiplier Go applies to findings in this category.
    # Values < 1.0 shrink confidence (category is mostly no-signal); > 1.0 boost it.
    confidenceMultiplier: float
    # Predicted TP probability from the gradient-boosted classifier (0–1).
    # Equals -1 when the classifier could not be fit (insufficient data).
    tpProbability: float
    probeCount: int


class CalibrateProbeSignalsResponse(BaseModel):
    multipliers: Dict[str, float]  # category -> confidenceMultiplier
    categoryDetails: List[CategoryCalibration] = Field(default_factory=list)
    calibrated: bool  # False when deps missing or gate disabled


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


@app.middleware("http")
async def _require_sidecar_token(request: Request, call_next):
    if SIDECAR_AUTH_TOKEN and request.url.path not in _AUTH_EXEMPT_PATHS:
        provided = _extract_bearer_token(request)
        if not provided or not hmac.compare_digest(provided, SIDECAR_AUTH_TOKEN):
            return JSONResponse(
                status_code=401,
                content={"detail": "invalid or missing sidecar token"},
            )
    return await call_next(request)


@app.get("/health")
def health() -> Dict[str, str]:
    if onnx_scorer.ready:
        return {"status": "ok", "mode": "onnx", "modelPath": onnx_scorer.model_path, "scoringMode": SCORING_MODE}
    # Avoid exposing internal loader/runtime error detail over unauthenticated health probes.
    return {"status": "ok", "mode": "heuristic", "reason": "onnx unavailable", "scoringMode": SCORING_MODE}


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


@app.post("/v1/calibrate-probe-signals", response_model=CalibrateProbeSignalsResponse)
def calibrate_probe_signals(req: CalibrateProbeSignalsRequest) -> CalibrateProbeSignalsResponse:
    """Compute per-category Bayesian confidence calibration from probe records.

    Uses a Beta-distribution posterior on the no-signal rate and (when enough
    data is available) a GradientBoostingClassifier to estimate the TP
    probability for each category.  Returns per-category multipliers that the
    Go backend applies to finding confidence scores before enrichment.
    """
    if not _CALIBRATE_ENABLED or not _CALIBRATION_DEPS_OK:
        return CalibrateProbeSignalsResponse(multipliers={}, categoryDetails=[], calibrated=False)

    records = req.probeRecords
    if not records:
        return CalibrateProbeSignalsResponse(multipliers={}, categoryDetails=[], calibrated=True)

    return _compute_calibration(records)


def _compute_calibration(records: List[ProbeRecordInput]) -> CalibrateProbeSignalsResponse:
    """Core calibration logic — only called when deps are available and gate is on."""
    from scipy.stats import beta as scipy_beta  # type: ignore  # noqa: F811
    from sklearn.ensemble import GradientBoostingClassifier  # type: ignore  # noqa: F811

    # --- Aggregate per-category counts ---
    # Beta prior: Beta(1,1) = uniform prior on p_no_signal.
    # Posterior given n_no_signal successes out of n_total trials:
    #   Beta(1 + n_no_signal, 1 + n_total - n_no_signal)
    BETA_ALPHA_PRIOR = 1.0
    BETA_BETA_PRIOR = 1.0
    CI_LEVEL = 0.95
    _OUTCOME_CONFIRMED = "confirmed"

    # Collect per-category stats and feature rows for the GB classifier.
    cat_total: Dict[str, int] = {}
    cat_no_signal: Dict[str, int] = {}
    cat_confirmed: Dict[str, int] = {}

    # Numeric encoding for outcome → classifier feature
    outcome_map: Dict[str, float] = {
        "confirmed": 1.0,
        "near_miss": 0.75,
        "waf_blocked": 0.5,
        "server_error": 0.4,
        "error": 0.2,
        "no_signal": 0.0,
    }

    # All categories seen across records (for GB training)
    all_cats = sorted({r.category for r in records if r.category})
    cat_idx = {c: i for i, c in enumerate(all_cats)}

    X_rows: List[List[float]] = []
    y_rows: List[int] = []

    for r in records:
        cat = r.category or ""
        if not cat:
            continue
        cat_total[cat] = cat_total.get(cat, 0) + 1
        if r.outcome == "no_signal":
            cat_no_signal[cat] = cat_no_signal.get(cat, 0) + 1
        if r.outcome == _OUTCOME_CONFIRMED:
            cat_confirmed[cat] = cat_confirmed.get(cat, 0) + 1

        # Feature: [category_one_hot_idx_normalised, outcome_score, status_class]
        outcome_score = outcome_map.get(r.outcome, 0.3)
        status_class = min(r.statusCode // 100, 5) / 5.0
        X_rows.append([cat_idx.get(cat, 0) / max(len(all_cats), 1), outcome_score, status_class])
        # Label: 1 if this probe's category eventually has a confirmed record
        # (computed after we finish scanning all records)
        y_rows.append(0)  # filled in below

    # Fill GB labels: 1 for rows whose category has at least one confirmed probe.
    confirmed_cats = {c for c, n in cat_confirmed.items() if n > 0}
    for i, r in enumerate(records):
        if r.category in confirmed_cats:
            y_rows[i] = 1

    # --- Fit the GB classifier if we have enough data ---
    _GB_MIN_SAMPLES = 10
    gb_proba: Dict[str, float] = {}
    if len(X_rows) >= _GB_MIN_SAMPLES and len(set(y_rows)) == 2:
        try:
            clf = GradientBoostingClassifier(n_estimators=50, max_depth=3, random_state=0)
            clf.fit(X_rows, y_rows)
            # Predict TP probability for each category using its mean feature row.
            for cat in all_cats:
                cat_rows = [X_rows[i] for i, r in enumerate(records) if r.category == cat]
                if cat_rows:
                    mean_feat = [sum(col) / len(cat_rows) for col in zip(*cat_rows)]
                    prob = float(clf.predict_proba([mean_feat])[0][1])
                    gb_proba[cat] = prob
        except Exception as exc:  # pragma: no cover
            logger.warning("GradientBoostingClassifier fit failed: %s", exc)

    # --- Compute per-category calibration ---
    details: List[CategoryCalibration] = []
    multipliers: Dict[str, float] = {}

    for cat in all_cats:
        n = cat_total.get(cat, 0)
        k = cat_no_signal.get(cat, 0)
        # Beta posterior parameters
        alpha = BETA_ALPHA_PRIOR + k
        beta_param = BETA_BETA_PRIOR + (n - k)
        # Posterior mean of the no-signal rate
        no_signal_mean = alpha / (alpha + beta_param)
        # 95% credible interval (equal-tailed)
        lower_ci = float(scipy_beta.ppf((1 - CI_LEVEL) / 2, alpha, beta_param))
        upper_ci = float(scipy_beta.ppf(1 - (1 - CI_LEVEL) / 2, alpha, beta_param))

        tp_prob = gb_proba.get(cat, -1.0)

        # Multiplier derivation:
        # - High no-signal rate → lower confidence (multiplier < 1)
        # - Confirmed probes (tp_prob high) → higher confidence (multiplier > 1)
        # We use (1 - posterior_no_signal_mean) as the base signal fraction,
        # and blend in the GB TP probability when available.
        signal_fraction = 1.0 - no_signal_mean
        if tp_prob >= 0:
            # Weight GB at 60%, Beta at 40%
            blended = 0.6 * tp_prob + 0.4 * signal_fraction
        else:
            blended = signal_fraction

        # Map blended ∈ [0,1] → multiplier ∈ [0.5, 1.5]
        multiplier = 0.5 + blended

        # Phase 4: nudge the multiplier by the average evidence-quality
        # signal for this category. evidenceValid + differentialConfirmed
        # count as positive evidence; a dominant surfaceGapReason of
        # "not_probed" pulls the multiplier down because the category is
        # observed under low coverage.
        cat_records = [r for r in records if r.category == cat]
        if cat_records:
            valid_share = sum(1 for r in cat_records if getattr(r, "evidenceValid", False)) / len(cat_records)
            diff_share = sum(1 for r in cat_records if getattr(r, "differentialConfirmed", False)) / len(cat_records)
            gap_penalty = sum(1 for r in cat_records if getattr(r, "surfaceGapReason", "") == "not_probed") / len(cat_records)
            multiplier += 0.10 * valid_share
            multiplier += 0.15 * diff_share
            multiplier -= 0.05 * gap_penalty
        # Clamp back into the documented [0.5, 1.5] band.
        if multiplier < 0.5:
            multiplier = 0.5
        if multiplier > 1.5:
            multiplier = 1.5
        multiplier = round(multiplier, 4)

        details.append(CategoryCalibration(
            category=cat,
            noSignalRate=round(no_signal_mean, 4),
            noSignalRateLower=round(lower_ci, 4),
            noSignalRateUpper=round(upper_ci, 4),
            confidenceMultiplier=multiplier,
            tpProbability=round(tp_prob, 4),
            probeCount=n,
        ))
        multipliers[cat] = multiplier

    logger.info(
        "calibrate-probe-signals categories=%d total_records=%d confirmed_cats=%d gb_fit=%s",
        len(all_cats),
        len(records),
        len(confirmed_cats),
        bool(gb_proba),
    )
    return CalibrateProbeSignalsResponse(
        multipliers=multipliers,
        categoryDetails=details,
        calibrated=True,
    )


def score_findings_internal(findings: List[Finding]) -> List[ScoredFinding]:
    scored: List[ScoredFinding] = []
    model_scores = onnx_scorer.predict(findings) if findings else None
    model_shadow_deltas: List[float] = []

    for idx, f in enumerate(findings):
        text = normalize(f"{f.title} {f.description} {f.evidence}")
        heuristic_score = severity_base(f.severity) + category_weight(f.category)

        for keyword, weight in keyword_weights().items():
            if keyword in text:
                heuristic_score += weight

        heuristic_score = clamp01(heuristic_score)

        model_score = None
        if model_scores and idx < len(model_scores):
            model_score = clamp01(float(model_scores[idx]))

        if SCORING_MODE == "heuristic" or model_score is None:
            score = heuristic_score
            confidence = clamp01(0.45 + score * 0.45)
        elif SCORING_MODE == "shadow":
            # Keep production output deterministic while logging model-vs-heuristic drift.
            score = heuristic_score
            confidence = clamp01(0.45 + score * 0.45)
            model_shadow_deltas.append(abs(model_score - heuristic_score))
        else:
            # Blend model probability with current deterministic score for stable behavior.
            score = clamp01(0.65 * model_score + 0.35 * heuristic_score)
            confidence = clamp01(0.55 + score * 0.40)

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
    if SCORING_MODE == "shadow" and model_shadow_deltas:
        avg_delta = sum(model_shadow_deltas) / float(len(model_shadow_deltas))
        logger.info(
            "ML shadow scoring completed findings=%d avg_abs_delta=%.4f mode=%s model_ready=%s",
            len(model_shadow_deltas),
            avg_delta,
            SCORING_MODE,
            onnx_scorer.ready,
        )
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
