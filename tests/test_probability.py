from __future__ import annotations

import importlib.util
import random
import unittest
from pathlib import Path


SOLVER = Path(__file__).parents[1] / (
    "ctf_challenges/cryptohack_archive/solvers/2022_probability_solve.py"
)


def load_solver():
    spec = importlib.util.spec_from_file_location("probability_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProbabilityPlannerTests(unittest.TestCase):
    def test_round_options_include_bust_and_stand(self) -> None:
        solver = load_solver()
        scale = solver.SCALE
        stream = [int(0.6 * scale), int(0.6 * scale), int(0.1 * scale)] * 20
        options = solver._round_options(stream, stream[0], 1)
        self.assertEqual(options[0][2], "s")
        self.assertTrue(any(action == "h" and not won for _, won, action in options))

    def test_dynamic_plan_replays_on_same_stream(self) -> None:
        solver = load_solver()
        scale = solver.SCALE
        rng = random.Random(0xC0FFEE)
        stream = [int(rng.random() * scale) for _ in range(2000)]
        expected_wins, actions = solver._plan(stream, stream[0], 1, 40)
        index = 1
        wins = 0
        for round_no, action in enumerate(actions):
            total = stream[index - 1] if round_no == 0 else stream[index]
            if round_no:
                index += 1
            for character in action:
                if character == "h":
                    total += stream[index]
                    index += 1
                    if total >= scale:
                        break
                else:
                    index, won = solver._dealer_end(stream, total, index)
                    wins += int(won)
                    break
        self.assertEqual(wins, expected_wins)


if __name__ == "__main__":
    unittest.main()
