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
    "rsa_secret_sharing_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_rsa_secret_sharing_verify.py",
)
RECORD = ROOT / "ctf_challenges/cryptohack_archive/files/2022/rsa_secret_sharing-wacon2022/live_replay.json"


class RsaSecretSharingTests(unittest.TestCase):
    def test_live_transcript_is_independently_reproducible(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        VERIFY.verify(RECORD, record["flag"])

    def test_factor_mutation_is_rejected(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        record["factors"][0][0] += 1
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutated.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(AssertionError):
                VERIFY.verify(path)


if __name__ == "__main__":
    unittest.main()
