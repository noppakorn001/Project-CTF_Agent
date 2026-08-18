import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/no_padding_no_problem/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("no_padding_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoPaddingSolverTests(unittest.TestCase):
    def test_recover_without_wrap(self):
        solver = load_solver()
        self.assertEqual(solver.recover_message(101, 24), 12)

    def test_recover_with_one_wrap(self):
        solver = load_solver()
        # 2*60 mod 101 = 19; odd response means add n before halving.
        self.assertEqual(solver.recover_message(101, 19), 60)


if __name__ == "__main__":
    unittest.main()
