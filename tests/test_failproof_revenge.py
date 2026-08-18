from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = load(
    "failproof_revenge_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_failproof_revenge_verify.py",
)
RECORD = ROOT / "ctf_challenges/cryptohack_archive/files/2022/failproof_revenge-sekaictf202/live_replay.json"


class FailProofRevengeTests(unittest.TestCase):
    def test_live_statistical_replay(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        VERIFY.verify(RECORD, record["flag"])

    def test_candidate_mutation_is_rejected(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            # Keep captures next to the temporary record so verifier path
            # resolution remains deterministic without touching the originals.
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(AssertionError):
                VERIFY.verify(RECORD, record["flag"] + "x")


if __name__ == "__main__":
    unittest.main()
