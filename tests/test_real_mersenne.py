import importlib.util
import random
import unittest
from pathlib import Path


SOLVER = Path(__file__).parents[1] / (
    "ctf_challenges/cryptohack_archive/solvers/2021_real_mersenne_solve.py"
)


def load_solver():
    spec = importlib.util.spec_from_file_location("real_mersenne_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RealMersenneRegressionTests(unittest.TestCase):
    def test_full_53_bit_recovery_matches_mt_state(self):
        solver = load_solver()
        rng = random.Random(0xBEEF)
        original = [rng.getrandbits(32) for _ in range(solver.N)]
        observed = []
        replay_state = solver.twist_int(original)
        index = 0
        for _ in range(700):
            value, index = solver.random53(replay_state, index)
            observed.append(value)

        recovered = solver.solve_state(observed)
        # Some low bits of the seed state are not observable through
        # random.random()'s 27/26-bit truncation.  They may differ while the
        # recovered state still predicts the complete 2000-round transcript.
        original_replay = solver.twist_int(original)
        recovered_replay = solver.twist_int(recovered)
        original_index = 0
        recovered_index = 0
        for _ in range(2000):
            expected, original_index = solver.random53(original_replay, original_index)
            actual, recovered_index = solver.random53(recovered_replay, recovered_index)
            self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
