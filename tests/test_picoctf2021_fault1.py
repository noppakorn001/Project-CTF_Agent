import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/its_not_my_fault_1/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("fault1_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FaultOneTests(unittest.TestCase):
    def test_pow_small_fixture(self):
        solver = load_solver()
        self.assertEqual(solver.solve_pow("12345", "57cd2a", limit=1), "123450")

    def test_bound_is_20_bits(self):
        solver = load_solver()
        self.assertEqual(solver.DP_BOUND, 1 << 20)

    def test_worker_detects_a_toy_factor(self):
        solver = load_solver()
        # For n=11*13, base=2 and message=13 are congruent to one another
        # modulo p=11 but not modulo q=13; d_p=1 therefore yields gcd 11.
        result = solver._pow_worker((1, 4, 2, 13, 11 * 13))
        self.assertIsNotNone(result)
        self.assertIn(result[1], (11, 13))


if __name__ == "__main__":
    unittest.main()
