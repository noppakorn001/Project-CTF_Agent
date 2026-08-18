from __future__ import annotations

import hashlib
import importlib.util
import random
import unittest
from pathlib import Path


SOLVER = Path(__file__).parents[1] / "ctf_challenges/cryptohack_archive/solvers/2022_maybe_someday_solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("maybe_someday_solver", SOLVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Maybe Someday solver")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MaybeSomedayBitsetTests(unittest.TestCase):
    def test_bitset_filter_matches_the_oracle_predicate(self):
        solver = load_solver()
        digests, by_byte = solver.candidate_table()
        rng = random.Random(2022)
        constraints = [
            (target, solver.non_adjacent_indices(rng))
            for target in solver.TESTS
        ]
        secret_value = 0xBEEF
        secret_digest = hashlib.sha512(secret_value.to_bytes(2, "big")).hexdigest().encode()
        outcomes = [
            any(secret_digest[index] == target for index in indices)
            for target, indices in constraints
        ]

        candidates = solver.filter_candidates(constraints, outcomes, digests, by_byte)
        self.assertIn(
            (secret_digest, secret_value.to_bytes(2, "big")),
            candidates,
        )

        expected = {
            (digest, value.to_bytes(2, "big"))
            for value, digest in enumerate(digests)
            if all(
                any(digest[index] == target for index in indices) == outcome
                for (target, indices), outcome in zip(constraints, outcomes)
            )
        }
        self.assertEqual(set(candidates), expected)


if __name__ == "__main__":
    unittest.main()
