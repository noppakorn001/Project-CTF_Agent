import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/dachshund_attacks/solve.py"
VALUES = SOLVER.parent / "values"


def load_solver():
    spec = importlib.util.spec_from_file_location("dachshund_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DachshundSolverTests(unittest.TestCase):
    def test_wiener_replay_and_factor_validation(self):
        solver = load_solver()
        flag, d, p, q = solver.solve(VALUES.read_text())
        self.assertEqual(flag, "picoCTF{proving_wiener_4755a2a}")
        values = solver.parse_decimal_fields(VALUES.read_text())
        self.assertEqual(p * q, values["n"])
        self.assertEqual((values["e"] * d - 1) % ((p - 1) * (q - 1)), 0)


if __name__ == "__main__":
    unittest.main()
