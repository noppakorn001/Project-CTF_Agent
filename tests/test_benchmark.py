from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from ctf_agent.__main__ import main
from ctf_agent.benchmark import (
    aggregate_metrics,
    blind_payload,
    load_manifest,
    render_report,
    validate_manifest,
)


class BenchmarkTests(unittest.TestCase):
    def make_dataset(self, root: Path) -> Path:
        challenge = root / "crypto_001"
        (challenge / "artifacts").mkdir(parents=True)
        (challenge / "description.txt").write_text(
            "Recover the message from the supplied RSA relation.", encoding="utf-8"
        )
        (challenge / "artifacts" / "input.bin").write_bytes(b"bounded-artifact")
        manifest_path = root / "manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "benchmark_id": "test-benchmark",
                    "primary": True,
                    "expected_tiers": {
                        "intermediate": 10,
                        "advanced": 10,
                        "expert": 10,
                    },
                    "challenges": [
                        {
                            "id": "crypto_001",
                            "tier": "intermediate",
                            "description": "crypto_001/description.txt",
                            "artifacts_dir": "crypto_001/artifacts",
                            "flag_format": "CTF{...}",
                            "source_ref": "official-artifact-hash-only",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return manifest_path

    def test_manifest_validation_and_blind_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(self.make_dataset(root))
            self.assertEqual(validate_manifest(manifest, root), [])
            payload = blind_payload(manifest, "crypto_001", root)
            self.assertEqual(payload["challenge_id"], "crypto_001")
            self.assertNotIn("tier", payload)
            self.assertNotIn("source_ref", payload)
            self.assertEqual(payload["artifacts"][0]["id"], "artifact_000")
            self.assertEqual(payload["artifacts"][0]["size"], len(b"bounded-artifact"))

    def test_primary_manifest_rejects_contamination_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = self.make_dataset(root)
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            raw["challenges"][0]["source_ref"] = "copied writeup"
            manifest_path.write_text(json.dumps(raw), encoding="utf-8")
            errors = validate_manifest(load_manifest(manifest_path), root)
            self.assertTrue(any("forbidden marker" in error for error in errors))

    def test_metrics_exclude_contaminated_and_render_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(self.make_dataset(root))
            results = [
                {
                    "challenge_id": "crypto_001",
                    "tier": "intermediate",
                    "status": "SOLVED_CONFIRMED",
                    "solve_time_seconds": 120,
                    "token_cost": 300,
                    "tool_calls": 4,
                    "failed_hypotheses": 1,
                    "solver_attempts": 1,
                    "confidence_before": 0.2,
                    "confidence_after": 0.95,
                    "technique": "rsa/exact-low-exponent",
                },
                {
                    "challenge_id": "crypto_001",
                    "tier": "intermediate",
                    "status": "CONTAMINATED",
                },
            ]
            metrics = aggregate_metrics(results, manifest)
            self.assertEqual(metrics["total_records"], 2)
            self.assertEqual(metrics["valid_records"], 1)
            self.assertEqual(metrics["contaminated_records"], 1)
            self.assertEqual(metrics["solved"], 1)
            self.assertEqual(metrics["solve_rate"], 1.0)
            self.assertIn("rsa/exact-low-exponent", metrics["technique_distribution"])
            report = render_report(manifest, results)
            self.assertIn("# Competition Readiness Level", report)
            self.assertIn("CONTAMINATED", report)

    def test_cli_report_requires_clean_manifest_and_writes_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = self.make_dataset(root)
            results_path = root / "results.jsonl"
            results_path.write_text(
                json.dumps(
                    {
                        "challenge_id": "crypto_001",
                        "tier": "intermediate",
                        "status": "FAILED",
                        "solve_time_seconds": 10,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            output_path = root / "report.md"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(
                        [
                            "benchmark",
                            "report",
                            "--manifest",
                            str(manifest_path),
                            "--root",
                            str(root),
                            "--results",
                            str(results_path),
                            "--output",
                            str(output_path),
                        ]
                    ),
                    0,
                )
            self.assertTrue(output_path.is_file())
            self.assertIn('"solved": 0', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
