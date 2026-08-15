from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib import request

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper


SCHEMA_VERSION = "v1"
FEATURE_DIMS = 8
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*)(bearer|basic)\s+[A-Za-z0-9\-._~+/=]+"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9\-._~+/=]+['\"]?"),
    re.compile(r"(?i)(cookie\s*:\s*)[^;\n\r]+"),
    re.compile(r"https?://[^\s/$.?#].[^\s]*"),
]


@dataclass
class Metrics:
    count: int
    accuracy: float
    precision: float
    recall: float
    auc: float
    logloss: float

    def as_dict(self) -> Dict[str, float | int]:
        return {
            "count": self.count,
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "auc": round(self.auc, 4),
            "logloss": round(self.logloss, 4),
        }


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def read_dataset_from_api(api_base: str, api_key: str, limit: int) -> Dict[str, Any]:
    url = f"{api_base.rstrip('/')}/api/ml/engagements?limit={limit}"
    req = request.Request(url, method="GET")
    if api_key.strip():
        req.add_header("Authorization", f"Bearer {api_key.strip()}")
    with request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def quality_report(dataset: Dict[str, Any], min_records: int) -> Dict[str, Any]:
    records = dataset.get("records") or []
    issues: List[str] = []
    warnings: List[str] = []

    if len(records) < min_records:
        issues.append(f"record_count_below_min: got={len(records)} min={min_records}")

    required_record_fields = {"scanId", "targetHash", "findings", "labels"}
    for idx, record in enumerate(records[:2000]):
        missing = sorted(required_record_fields - set(record.keys()))
        if missing:
            issues.append(f"record_{idx}_missing_fields={missing}")
            break

    positives = 0
    negatives = 0
    feedback_count = 0
    redaction_issues = 0
    for record in records:
        labels = ((record.get("labels") or {}).get("prioritizationScore") or {})
        findings = record.get("findings") or []
        feedback = record.get("feedback") or []
        feedback_count += len(feedback)
        for finding in findings:
            fid = (finding.get("id") or "").strip()
            label_score = labels.get(fid, 0.0)
            label = 1 if float(label_score) >= 0.6 else 0
            outcome = feedback_label(feedback, fid)
            if outcome is not None:
                label = outcome
            if label == 1:
                positives += 1
            else:
                negatives += 1
            if contains_unredacted_secret(finding.get("title", "")) or contains_unredacted_secret(
                finding.get("evidence", "")
            ):
                redaction_issues += 1
        for item in feedback:
            if contains_unredacted_secret(item.get("notes", "")):
                redaction_issues += 1

    total_labels = positives + negatives
    if total_labels == 0:
        issues.append("no_training_labels_derived")
    else:
        pos_ratio = positives / total_labels
        if pos_ratio < 0.05 or pos_ratio > 0.95:
            warnings.append(f"class_imbalance_ratio={pos_ratio:.3f}")

    if redaction_issues > 0:
        issues.append(f"redaction_failures={redaction_issues}")

    return {
        "recordCount": len(records),
        "feedbackCount": feedback_count,
        "labelCount": total_labels,
        "positiveLabels": positives,
        "negativeLabels": negatives,
        "issues": issues,
        "warnings": warnings,
    }


def contains_unredacted_secret(value: str) -> bool:
    compact = " ".join(str(value or "").split())
    if not compact:
        return False
    lowered = compact.lower()
    if "[redacted]" in lowered:
        return False
    return any(p.search(compact) for p in SECRET_PATTERNS)


def normalize(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


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


def finding_features(finding: Dict[str, Any]) -> List[float]:
    text = normalize(f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('evidence', '')}")
    keyword_hit_count = 0.0
    keyword_weight_sum = 0.0
    for kw, wt in keyword_weights().items():
        if kw in text:
            keyword_hit_count += 1.0
            keyword_weight_sum += wt
    title_len = min(len(str(finding.get("title", ""))), 200) / 200.0
    desc_len = min(len(str(finding.get("description", ""))), 600) / 600.0
    rec_len = min(len(str(finding.get("recommendation", ""))), 300) / 300.0
    return [
        severity_base(str(finding.get("severity", "info"))),
        category_weight(str(finding.get("category", ""))),
        clamp01(keyword_weight_sum),
        clamp01(keyword_hit_count / 8.0),
        clamp01(title_len),
        clamp01(desc_len),
        clamp01(rec_len),
        1.0,
    ]


def feedback_label(feedback: List[Dict[str, Any]], finding_id: str) -> int | None:
    fid = finding_id.strip().lower()
    if not fid:
        return None
    for item in feedback:
        if normalize(item.get("findingId", "")) != fid:
            continue
        outcome = normalize(item.get("outcome", ""))
        reason = normalize(item.get("reason", ""))
        notes = item.get("notes", "")
        if not outcome and notes:
            try:
                parsed = json.loads(str(notes))
                outcome = normalize(parsed.get("outcome", ""))
                if not reason:
                    reason = normalize(parsed.get("reason", "") or parsed.get("decision", ""))
            except Exception:
                pass
        if outcome == "accepted":
            return 1
        if outcome in {"rejected", "duplicate", "informative", "suppressed", "na", "n/a", "not_applicable", "not applicable"}:
            return 0
        if reason in {"operator_accepted", "operator_verified"}:
            return 1
        if reason in {"operator_rejected", "operator_suppressed", "false_positive", "duplicate"}:
            return 0
    return None


def build_examples(dataset: Dict[str, Any]) -> Tuple[np.ndarray, np.ndarray, List[str], Dict[str, Any]]:
    records = dataset.get("records") or []
    features: List[List[float]] = []
    labels: List[int] = []
    keys: List[str] = []
    label_source = {"feedback": 0, "heuristic": 0}
    for record in records:
        scan_id = str(record.get("scanId", "")).strip()
        findings = record.get("findings") or []
        score_by_id = ((record.get("labels") or {}).get("prioritizationScore") or {})
        feedback = record.get("feedback") or []
        for finding in findings:
            fid = str(finding.get("id", "")).strip()
            if not fid:
                continue
            label = feedback_label(feedback, fid)
            if label is not None:
                label_source["feedback"] += 1
            else:
                score = float(score_by_id.get(fid, 0.0))
                label = 1 if score >= 0.6 else 0
                label_source["heuristic"] += 1
            features.append(finding_features(finding))
            labels.append(label)
            keys.append(f"{scan_id}|{fid}")
    if not features:
        return np.zeros((0, FEATURE_DIMS), dtype=np.float32), np.zeros((0,), dtype=np.float32), keys, label_source
    return np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.float32), keys, label_source


def split_indices(keys: Iterable[str]) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    train: List[int] = []
    val: List[int] = []
    test: List[int] = []
    for idx, key in enumerate(keys):
        bucket = int(hashlib.sha256(key.encode("utf-8")).hexdigest()[:8], 16) % 100
        if bucket < 70:
            train.append(idx)
        elif bucket < 85:
            val.append(idx)
        else:
            test.append(idx)
    return np.asarray(train), np.asarray(val), np.asarray(test)


def sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


def train_logreg(x: np.ndarray, y: np.ndarray, *, epochs: int = 400, lr: float = 0.08, l2: float = 1e-3) -> Tuple[np.ndarray, float]:
    if len(x) == 0:
        return np.zeros((FEATURE_DIMS,), dtype=np.float32), 0.0
    weights = np.zeros((x.shape[1],), dtype=np.float64)
    bias = 0.0
    n = float(len(x))
    for _ in range(epochs):
        logits = x @ weights + bias
        probs = sigmoid(logits)
        err = probs - y
        grad_weights = (x.T @ err) / n + (l2 * weights)
        grad_bias = float(np.sum(err) / n)
        weights -= lr * grad_weights
        bias -= lr * grad_bias
    return weights.astype(np.float32), float(bias)


def baseline_probs(x: np.ndarray) -> np.ndarray:
    if len(x) == 0:
        return np.zeros((0,), dtype=np.float32)
    raw = 0.45 * x[:, 0] + 0.20 * x[:, 1] + 0.35 * x[:, 2]
    return np.clip(raw, 0.0, 1.0).astype(np.float32)


def metrics(y_true: np.ndarray, y_prob: np.ndarray) -> Metrics:
    if len(y_true) == 0:
        return Metrics(count=0, accuracy=0.0, precision=0.0, recall=0.0, auc=0.0, logloss=1.0)
    eps = 1e-7
    prob = np.clip(y_prob.astype(np.float64), eps, 1 - eps)
    pred = (prob >= 0.5).astype(np.float32)
    accuracy = float(np.mean((pred == y_true).astype(np.float32)))
    true_pos = float(np.sum((pred == 1) & (y_true == 1)))
    false_pos = float(np.sum((pred == 1) & (y_true == 0)))
    false_neg = float(np.sum((pred == 0) & (y_true == 1)))
    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0.0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) > 0 else 0.0
    logloss = float(-np.mean(y_true * np.log(prob) + (1 - y_true) * np.log(1 - prob)))
    auc = roc_auc(y_true, prob)
    return Metrics(count=int(len(y_true)), accuracy=accuracy, precision=precision, recall=recall, auc=auc, logloss=logloss)


def roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    pos = y_score[y_true == 1]
    neg = y_score[y_true == 0]
    if len(pos) == 0 or len(neg) == 0:
        return 0.5
    comparisons = (pos[:, None] > neg[None, :]).sum()
    ties = (pos[:, None] == neg[None, :]).sum()
    return float((comparisons + 0.5 * ties) / (len(pos) * len(neg)))


def export_onnx(weights: np.ndarray, bias: float, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    input_tensor_info = helper.make_tensor_value_info("input", TensorProto.FLOAT, ["N", FEATURE_DIMS])
    output_tensor_info = helper.make_tensor_value_info("output", TensorProto.FLOAT, ["N", 1])
    weights_initializer = numpy_helper.from_array(weights.reshape((FEATURE_DIMS, 1)).astype(np.float32), name="W")
    bias_initializer = numpy_helper.from_array(np.asarray([bias], dtype=np.float32), name="B")
    graph = helper.make_graph(
        nodes=[
            helper.make_node("MatMul", ["input", "W"], ["matmul_out"]),
            helper.make_node("Add", ["matmul_out", "B"], ["logits"]),
            helper.make_node("Sigmoid", ["logits"], ["output"]),
        ],
        name="risk_logreg",
        inputs=[input_tensor_info],
        outputs=[output_tensor_info],
        initializer=[weights_initializer, bias_initializer],
    )
    model = helper.make_model(graph, producer_name="auto-bughunter-training-pipeline", opset_imports=[helper.make_opsetid("", 13)])
    onnx.checker.check_model(model)
    onnx.save(model, str(out_path))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def update_registry(registry_path: Path, entry: Dict[str, Any]) -> None:
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    data: Dict[str, Any] = {"schemaVersion": 1, "models": []}
    if registry_path.exists():
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    models = data.get("models") or []
    models.append(entry)
    data["models"] = models[-100:]
    registry_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def archive_checkpoint(
    models_dir: Path,
    model_version: str,
    candidate_model: Path,
    output_dir: Path,
    artifact_paths: Dict[str, Path],
) -> Path:
    checkpoint_dir = models_dir / "checkpoints" / model_version
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate_model, checkpoint_dir / "risk.onnx")
    shutil.copyfile(output_dir / "manifest.json", checkpoint_dir / "manifest.json")
    for name, path in artifact_paths.items():
        if path.exists():
            shutil.copyfile(path, checkpoint_dir / path.name)
    (checkpoint_dir / "checkpoint_index.json").write_text(
        json.dumps(
            {
                "modelVersion": model_version,
                "artifacts": {name: str((checkpoint_dir / path.name)) for name, path in artifact_paths.items() if path.exists()},
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return checkpoint_dir


def promote_model(candidate_model: Path, models_dir: Path, metadata: Dict[str, Any]) -> None:
    target = models_dir / "risk.onnx"
    shutil.copyfile(candidate_model, target)
    active = {"activeModel": metadata.get("modelVersion"), "promotedAt": datetime.now(timezone.utc).isoformat(), "metadata": metadata}
    (models_dir / "active_model.json").write_text(json.dumps(active, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Auto Bughunter ML training pipeline")
    p.add_argument("--api-base", default=os.getenv("TRAINING_API_BASE", "").strip())
    p.add_argument("--api-key", default=os.getenv("TRAINING_API_KEY", "").strip())
    p.add_argument("--limit", type=int, default=int(os.getenv("TRAINING_LIMIT", "500")))
    p.add_argument("--dataset-path", default=os.getenv("TRAINING_DATASET_PATH", "").strip())
    p.add_argument("--output-dir", default=os.getenv("TRAINING_OUTPUT_DIR", "/tmp/auto-bughunter-training"))
    p.add_argument("--models-dir", default=os.getenv("TRAINING_MODELS_DIR", "/models"))
    p.add_argument("--min-records", type=int, default=int(os.getenv("TRAINING_MIN_RECORDS", "20")))
    p.add_argument("--min-labels", type=int, default=int(os.getenv("TRAINING_MIN_LABELS", "100")))
    p.add_argument("--promotion-auc-delta", type=float, default=float(os.getenv("TRAINING_PROMOTION_AUC_DELTA", "0.01")))
    p.add_argument("--promotion-logloss-improvement", type=float, default=float(os.getenv("TRAINING_PROMOTION_LOGLOSS_IMPROVEMENT", "0.02")))
    p.add_argument("--max-precision-regression", type=float, default=float(os.getenv("TRAINING_MAX_PRECISION_REGRESSION", "0.02")))
    p.add_argument("--max-recall-regression", type=float, default=float(os.getenv("TRAINING_MAX_RECALL_REGRESSION", "0.02")))
    p.add_argument("--allow-quality-warnings", action="store_true")
    return p.parse_args()


def build_probe_config_snapshot(dataset: Dict[str, Any]) -> Dict[str, Any]:
    records = dataset.get("records") or []
    tool_stats: Dict[str, Dict[str, float]] = {}
    profiles: Dict[str, int] = {}
    for record in records:
        tool_options = record.get("toolOptions") or {}
        enabled = sorted([name for name, enabled in tool_options.items() if bool(enabled)])
        profile_key = ",".join(enabled) if enabled else "none"
        profiles[profile_key] = profiles.get(profile_key, 0) + 1
        for tool, enabled_flag in tool_options.items():
            cur = tool_stats.setdefault(tool, {"enabledCount": 0.0, "recordCount": 0.0})
            cur["recordCount"] += 1.0
            if bool(enabled_flag):
                cur["enabledCount"] += 1.0
    ordered_tools = {}
    for tool in sorted(tool_stats.keys()):
        cur = tool_stats[tool]
        count = cur["recordCount"] or 1.0
        ordered_tools[tool] = {
            "enabledCount": int(cur["enabledCount"]),
            "recordCount": int(cur["recordCount"]),
            "enabledRate": round(cur["enabledCount"] / count, 4),
        }
    top_profiles = [
        {"enabledTools": [] if key == "none" else key.split(","), "count": count}
        for key, count in sorted(profiles.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]
    return {
        "schemaVersion": 1,
        "recordsAnalyzed": len(records),
        "tools": ordered_tools,
        "profiles": top_profiles,
    }


def build_capability_matrix(dataset: Dict[str, Any]) -> Dict[str, Any]:
    records = dataset.get("records") or []
    by_category: Dict[str, Dict[str, float]] = {}
    benchmark_targets = set()
    for record in records:
        findings = record.get("findings") or []
        feedback = record.get("feedback") or []
        labels = ((record.get("labels") or {}).get("prioritizationScore") or {})
        benchmark_targets.add(str(record.get("targetHash", "")).strip())
        for finding in findings:
            category = normalize(finding.get("category", "")) or "uncategorized"
            bucket = by_category.setdefault(
                category,
                {
                    "findings": 0.0,
                    "positiveLabels": 0.0,
                    "negativeLabels": 0.0,
                    "accepted": 0.0,
                    "duplicates": 0.0,
                    "na": 0.0,
                    "informative": 0.0,
                },
            )
            bucket["findings"] += 1.0
            fid = str(finding.get("id", "")).strip()
            outcome = feedback_label(feedback, fid)
            if outcome is None:
                outcome = 1 if float(labels.get(fid, 0.0)) >= 0.6 else 0
            if outcome == 1:
                bucket["positiveLabels"] += 1.0
            else:
                bucket["negativeLabels"] += 1.0
            for item in feedback:
                if normalize(item.get("findingId", "")) != normalize(fid):
                    continue
                fb_outcome = normalize(item.get("outcome", ""))
                if fb_outcome == "accepted":
                    bucket["accepted"] += 1.0
                elif fb_outcome == "duplicate":
                    bucket["duplicates"] += 1.0
                elif fb_outcome in {"na", "n/a", "not_applicable", "not applicable"}:
                    bucket["na"] += 1.0
                elif fb_outcome == "informative":
                    bucket["informative"] += 1.0
    categories = []
    for category in sorted(by_category.keys()):
        bucket = by_category[category]
        total = bucket["findings"] or 1.0
        categories.append(
            {
                "category": category,
                "findingCount": int(bucket["findings"]),
                "positiveLabels": int(bucket["positiveLabels"]),
                "negativeLabels": int(bucket["negativeLabels"]),
                "accepted": int(bucket["accepted"]),
                "duplicates": int(bucket["duplicates"]),
                "na": int(bucket["na"]),
                "informative": int(bucket["informative"]),
                "detectionRate": round(bucket["positiveLabels"] / total, 4),
                "acceptedRate": round(bucket["accepted"] / total, 4),
            }
        )
    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "benchmarkTargets": len([item for item in benchmark_targets if item]),
        "categories": categories,
    }


def render_capability_matrix_markdown(matrix: Dict[str, Any]) -> str:
    lines = [
        "# Living Capability Matrix",
        "",
        f"- Generated at: {matrix.get('generatedAt', '')}",
        f"- Benchmark targets sampled: {matrix.get('benchmarkTargets', 0)}",
        "",
        "| Category | Findings | Detection rate | Accepted rate | Accepted | Duplicate | N/A | Informative |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in matrix.get("categories") or []:
        lines.append(
            "| {category} | {findingCount} | {detectionRate:.2%} | {acceptedRate:.2%} | {accepted} | {duplicates} | {na} | {informative} |".format(
                **item
            )
        )
    return "\n".join(lines) + "\n"


def evaluate_promotion_gate(model_metrics: Metrics, baseline_metrics: Metrics, args: argparse.Namespace) -> Tuple[bool, Dict[str, Any]]:
    promote, promotion_gate = evaluate_promotion_gate(model_metrics, baseline_metrics, args)
    return promote, promotion_gate


def main() -> int:
    args = parse_args()
    run_id = now_utc()
    output_dir = Path(args.output_dir).resolve() / run_id
    output_dir.mkdir(parents=True, exist_ok=True)
    dataset_path = output_dir / "engagements.dataset.json"

    if args.dataset_path:
        source_path = Path(args.dataset_path).resolve()
        dataset = json.loads(source_path.read_text(encoding="utf-8"))
    else:
        if not args.api_base:
            print("error: --api-base (or TRAINING_API_BASE) is required when --dataset-path is not provided", file=sys.stderr)
            return 2
        dataset = read_dataset_from_api(args.api_base, args.api_key, args.limit)

    dataset_path.write_text(json.dumps(dataset, indent=2) + "\n", encoding="utf-8")
    report = quality_report(dataset, args.min_records)
    quality_path = output_dir / "quality_report.json"
    quality_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if report["issues"]:
        print(f"quality_gate_failed: {report['issues']}", file=sys.stderr)
        return 3
    if report["warnings"] and not args.allow_quality_warnings:
        print(f"quality_gate_warning: {report['warnings']}", file=sys.stderr)
        return 4

    x, y, keys, label_source = build_examples(dataset)
    if len(x) < args.min_labels:
        print(f"error: not enough labels; got={len(x)} min={args.min_labels}", file=sys.stderr)
        return 5

    train_idx, val_idx, test_idx = split_indices(keys)
    if len(train_idx) == 0 or len(test_idx) == 0:
        print("error: split produced empty train/test sets", file=sys.stderr)
        return 6
    w, b = train_logreg(x[train_idx], y[train_idx])
    probs_test = sigmoid(x[test_idx] @ w + b)
    baseline_test = baseline_probs(x[test_idx])
    model_metrics = metrics(y[test_idx], probs_test)
    baseline_metrics = metrics(y[test_idx], baseline_test)

    metrics_doc = {
        "model": model_metrics.as_dict(),
        "baseline": baseline_metrics.as_dict(),
        "split": {"train": int(len(train_idx)), "val": int(len(val_idx)), "test": int(len(test_idx))},
        "labelSource": label_source,
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics_doc, indent=2) + "\n", encoding="utf-8")

    candidate_model = output_dir / "risk-candidate.onnx"
    export_onnx(w, b, candidate_model)

    probe_config_snapshot = build_probe_config_snapshot(dataset)
    probe_config_path = output_dir / "probe_config_snapshot.json"
    probe_config_path.write_text(json.dumps(probe_config_snapshot, indent=2) + "\n", encoding="utf-8")

    capability_matrix = build_capability_matrix(dataset)
    capability_matrix_path = output_dir / "capability_matrix.json"
    capability_matrix_path.write_text(json.dumps(capability_matrix, indent=2) + "\n", encoding="utf-8")
    capability_matrix_md_path = output_dir / "capability_matrix.md"
    capability_matrix_md_path.write_text(render_capability_matrix_markdown(capability_matrix), encoding="utf-8")

    dataset_checksum = sha256_file(dataset_path)
    candidate_checksum = sha256_file(candidate_model)
    model_version = f"risk-{run_id}"
    precision_regression = max(0.0, baseline_metrics.precision - model_metrics.precision)
    recall_regression = max(0.0, baseline_metrics.recall - model_metrics.recall)
    promotion_gate = {
        "maxPrecisionRegression": args.max_precision_regression,
        "maxRecallRegression": args.max_recall_regression,
        "precisionRegression": round(precision_regression, 4),
        "recallRegression": round(recall_regression, 4),
        "precisionGatePassed": precision_regression <= args.max_precision_regression,
        "recallGatePassed": recall_regression <= args.max_recall_regression,
        "aucDeltaRequired": args.promotion_auc_delta,
        "loglossImprovementRequired": args.promotion_logloss_improvement,
        "aucDelta": round(model_metrics.auc - baseline_metrics.auc, 4),
        "loglossImprovement": round(baseline_metrics.logloss - model_metrics.logloss, 4),
    }
    promote = (
        promotion_gate["precisionGatePassed"]
        and promotion_gate["recallGatePassed"]
        and (model_metrics.auc - baseline_metrics.auc) >= args.promotion_auc_delta
        and (baseline_metrics.logloss - model_metrics.logloss) >= args.promotion_logloss_improvement
    )

    manifest = {
        "schemaVersion": SCHEMA_VERSION,
        "runId": run_id,
        "dataset": {
            "path": str(dataset_path),
            "sha256": dataset_checksum,
            "recordCount": report["recordCount"],
            "labelCount": report["labelCount"],
            "source": "api" if not args.dataset_path else "file",
            "apiBase": args.api_base,
            "limit": args.limit,
        },
        "model": {
            "version": model_version,
            "candidatePath": str(candidate_model),
            "candidateSha256": candidate_checksum,
            "featureDims": FEATURE_DIMS,
            "inferenceContract": "[N,8] -> [N,1]",
            "promoted": promote,
        },
        "probeConfigSnapshot": {"path": str(probe_config_path)},
        "capabilityMatrix": {"jsonPath": str(capability_matrix_path), "markdownPath": str(capability_matrix_md_path)},
        "promotionGate": promotion_gate,
        "evaluation": metrics_doc,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    models_dir = Path(args.models_dir).resolve()
    checkpoint_dir = archive_checkpoint(
        models_dir,
        model_version,
        candidate_model,
        output_dir,
        {
            "dataset": dataset_path,
            "qualityReport": quality_path,
            "metrics": output_dir / "metrics.json",
            "probeConfigSnapshot": probe_config_path,
            "capabilityMatrixJson": capability_matrix_path,
            "capabilityMatrixMarkdown": capability_matrix_md_path,
        },
    )
    registry_path = models_dir / "registry.json"
    registry_entry = {
        "modelVersion": model_version,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "datasetSha256": dataset_checksum,
        "artifactSha256": candidate_checksum,
        "artifactPath": str(candidate_model),
        "checkpointPath": str(checkpoint_dir),
        "probeConfigSnapshotPath": str(checkpoint_dir / probe_config_path.name),
        "capabilityMatrixPath": str(checkpoint_dir / capability_matrix_path.name),
        "promoted": promote,
        "promotionGate": promotion_gate,
        "metrics": metrics_doc,
    }
    update_registry(registry_path, registry_entry)
    if promote:
        promote_model(candidate_model, models_dir, registry_entry)
        print(f"promoted model: {model_version}")
    else:
        print(f"model not promoted: {model_version}")
    print(f"training run artifacts: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
