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


SOLVE = load(
    "rsa_permutation_solve",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_rsa_permutation_solve.py",
)
VERIFY = load(
    "rsa_permutation_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_rsa_permutation_verify.py",
)
RECORD = ROOT / "ctf_challenges/cryptohack_archive/files/2022/rsa_permutation-wacon2022/live_replay.json"


class RSAPermutationTests(unittest.TestCase):
    def test_helper_reconstructs_live_factors(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        p, q, dp, dq, k, l = SOLVE.recover_factors(
            int(record["n"]), record["mapped_dp"], record["mapped_dq"]
        )
        self.assertEqual(p * q, int(record["n"]))
        self.assertEqual((p, q), (int(record["p"]), int(record["q"])))
        self.assertEqual((dp, dq), (int(record["dp"], 16), int(record["dq"], 16)))
        self.assertEqual((k, l), (record["k"], record["l"]))

    def test_independent_verifier_and_mutation_rejection(self) -> None:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
        VERIFY.verify(RECORD, record["flag"])
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "mutated.json"
            changed = dict(record)
            changed["flag"] = record["flag"] + "x"
            mutated.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(AssertionError):
                VERIFY.verify(mutated)


if __name__ == "__main__":
    unittest.main()
