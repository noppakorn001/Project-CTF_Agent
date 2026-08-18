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
    "calm_down_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2020_calm_down_verify.py",
)
RECORD = ROOT / "ctf_challenges/cryptohack_archive/files/2020/calm_down-hkcert_ctf2020/live_replay.json"


class CalmDownTests(unittest.TestCase):
    def test_fresh_ciphertext_reencryption(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        VERIFY.verify(RECORD, record["flag"])

    def test_mutated_plaintext_is_rejected(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        plaintext = bytearray.fromhex(record["plaintext_hex"])
        plaintext[-2] ^= 1
        record["plaintext_hex"] = bytes(plaintext).hex()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(AssertionError):
                VERIFY.verify(path)


if __name__ == "__main__":
    unittest.main()
