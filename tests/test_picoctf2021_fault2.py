import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/its_not_my_fault_2/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("fault2_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FaultTwoTests(unittest.TestCase):
    def test_pow_candidate_verifies(self):
        solver = load_solver()
        candidate = solver.solve_pow("12345", "57cd2a", limit=1)
        import hashlib

        self.assertEqual(candidate, "123450")
        self.assertTrue(hashlib.md5(candidate.encode()).hexdigest().endswith("57cd2a"))

    def test_small_pow_bound_rejects(self):
        solver = load_solver()
        with self.assertRaises(ValueError):
            solver.solve_pow("12345", "000000", limit=1)


if __name__ == "__main__":
    unittest.main()
