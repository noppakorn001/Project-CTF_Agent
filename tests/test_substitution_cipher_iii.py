from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
OUTPUT = ROOT / "ctf_challenges/cryptohack_archive/files/2021/substitution_cipher_iii-downu/output.txt"
SOLVER = ROOT / "ctf_challenges/cryptohack_archive/solvers/2021_substitution_cipher_iii_solve.py"
VERIFIER = ROOT / "ctf_challenges/cryptohack_archive/solvers/2021_substitution_cipher_iii_verify.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SubstitutionCipherIIITests(unittest.TestCase):
    def test_attack_replays_supplied_artifact(self):
        solver = load(SOLVER, "substitution_cipher_iii_solver")
        self.assertEqual(solver.solve(OUTPUT), "DUCTF{MQ_1s_fun_a5e39cf21a}")

    def test_independent_verifier_rejects_mutation(self):
        verifier = load(VERIFIER, "substitution_cipher_iii_verifier")
        with self.assertRaises(SystemExit):
            verifier.verify("DUCTF{MQ_1s_fun_a5e39cf20}", OUTPUT)


if __name__ == "__main__":
    unittest.main()
