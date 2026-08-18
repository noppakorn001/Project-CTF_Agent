from __future__ import annotations

import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SOLVERS = ROOT / "ctf_challenges" / "cryptohack_archive" / "solvers"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class UnrandomDsaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.solver = load("unrandom_dsa_solver_test", SOLVERS / "2023_unrandom_dsa_solve.py")
        cls.verifier = load("unrandom_dsa_verifier_test", SOLVERS / "2023_unrandom_dsa_verify.py")

    def test_known_subgroup_relation_and_signature(self) -> None:
        x = 4291796662813
        y = pow(self.solver.G, x, self.solver.P)
        self.assertEqual(self.solver.discrete_log_subgroup(y), x)
        signature = self.solver.dsa_signature(x)
        r = int.from_bytes(signature[:20], "big")
        s = int.from_bytes(signature[20:], "big")
        z = int.from_bytes(hashlib.sha256(b"sign me!").digest(), "big") >> 96
        w = pow(s, -1, self.solver.Q)
        u1, u2 = z * w % self.solver.Q, r * w % self.solver.Q
        # With y=g^x, the normal DSA verification expression is g^u1*y^u2.
        checked = (pow(self.solver.G, u1, self.solver.P)
                   * pow(y, u2, self.solver.P) % self.solver.P) % self.solver.Q
        self.assertEqual(checked, r)
        self.assertEqual(len(signature), 40)

    def test_verifier_has_no_solver_import(self) -> None:
        text = (SOLVERS / "2023_unrandom_dsa_verify.py").read_text()
        self.assertNotIn("unrandom_dsa_solve", text)


if __name__ == "__main__":
    unittest.main()
