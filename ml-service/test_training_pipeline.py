import argparse
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from app import training_pipeline as tp


class TrainingPipelineTests(unittest.TestCase):
    def test_metrics_include_precision_and_recall(self):
        y_true = np.asarray([1, 1, 0, 0], dtype=np.float32)
        y_prob = np.asarray([0.9, 0.7, 0.8, 0.1], dtype=np.float32)

        out = tp.metrics(y_true, y_prob)

        self.assertAlmostEqual(out.precision, 2 / 3, places=4)
        self.assertAlmostEqual(out.recall, 1.0, places=4)

    def test_build_probe_config_snapshot_and_capability_matrix(self):
        dataset = {
            "records": [
                {
                    "scanId": "scan-1",
                    "targetHash": "t-1",
                    "toolOptions": {"nuclei": True, "zap_baseline": False},
                    "findings": [{"id": "f-1", "category": "xss"}],
                    "feedback": [{"findingId": "f-1", "outcome": "accepted"}],
                    "labels": {"prioritizationScore": {"f-1": 0.9}},
                },
                {
                    "scanId": "scan-2",
                    "targetHash": "t-2",
                    "toolOptions": {"nuclei": True, "zap_baseline": True},
                    "findings": [{"id": "f-2", "category": "xss"}],
                    "feedback": [{"findingId": "f-2", "outcome": "duplicate"}],
                    "labels": {"prioritizationScore": {"f-2": 0.1}},
                },
            ]
        }

        snapshot = tp.build_probe_config_snapshot(dataset)
        matrix = tp.build_capability_matrix(dataset)

        self.assertEqual(snapshot["tools"]["nuclei"]["enabledCount"], 2)
        self.assertEqual(snapshot["tools"]["zap_baseline"]["enabledCount"], 1)
        self.assertEqual(matrix["categories"][0]["category"], "xss")
        self.assertEqual(matrix["categories"][0]["accepted"], 1)
        self.assertEqual(matrix["categories"][0]["duplicates"], 1)

    def test_evaluate_promotion_gate_blocks_large_precision_regression(self):
        args = argparse.Namespace(
            max_precision_regression=0.02,
            max_recall_regression=0.02,
            promotion_auc_delta=-1.0,
            promotion_logloss_improvement=-1.0,
        )
        model_metrics = tp.Metrics(count=10, accuracy=0.8, precision=0.7, recall=0.9, auc=0.8, logloss=0.2)
        baseline_metrics = tp.Metrics(count=10, accuracy=0.8, precision=0.8, recall=0.9, auc=0.7, logloss=0.3)

        promote, gate = tp.evaluate_promotion_gate(model_metrics, baseline_metrics, args)

        self.assertFalse(promote)
        self.assertFalse(gate["precisionGatePassed"])

    def test_archive_checkpoint_copies_phase_e_artifacts(self):
        with tempfile.TemporaryDirectory() as models_dir, tempfile.TemporaryDirectory() as output_dir:
            models_path = Path(models_dir)
            output_path = Path(output_dir)
            candidate_model = output_path / "risk-candidate.onnx"
            candidate_model.write_bytes(b"onnx")
            (output_path / "manifest.json").write_text("{}", encoding="utf-8")
            metrics_path = output_path / "metrics.json"
            metrics_path.write_text("{}", encoding="utf-8")
            probe_path = output_path / "probe_config_snapshot.json"
            probe_path.write_text("{}", encoding="utf-8")
            capability_path = output_path / "capability_matrix.json"
            capability_path.write_text("{}", encoding="utf-8")

            checkpoint_dir = tp.archive_checkpoint(
                models_path,
                "risk-test",
                candidate_model,
                output_path,
                {
                    "metrics": metrics_path,
                    "probeConfigSnapshot": probe_path,
                    "capabilityMatrixJson": capability_path,
                },
            )

            self.assertTrue((checkpoint_dir / "risk.onnx").exists())
            self.assertTrue((checkpoint_dir / "probe_config_snapshot.json").exists())
            self.assertTrue((checkpoint_dir / "capability_matrix.json").exists())


if __name__ == "__main__":
    unittest.main()
