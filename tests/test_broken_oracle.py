from __future__ import annotations

import importlib.util
import random
import unittest
from math import gcd
from pathlib import Path


SOLVER = Path(__file__).parents[1] / (
    "ctf_challenges/cryptohack_archive/solvers/2023_broken_oracle_solve.py"
)


def load_solver():
    spec = importlib.util.spec_from_file_location("broken_oracle_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BrokenOracleMathTests(unittest.TestCase):
    def test_quadratic_roots_and_jacobi(self) -> None:
        solver = load_solver()
        p, q = 1019, 1031  # both 3 mod 4
        c = 37
        m = 271
        self.assertEqual(gcd(m, p), 1)
        r = (m + c * pow(m, -1, p)) % p
        roots = solver.roots(r, c, p)
        self.assertIn(m % p, roots)
        self.assertIn((c * pow(m, -1, p)) % p, roots)

    def test_prompt_enc_parser_is_bounded_and_exact(self) -> None:
        solver = load_solver()
        parsed = solver.parse_enc(
            [b"decrypt(encrypt(input)):", b"r = 1", b"s = -1", b"t = 0"]
        )
        self.assertEqual(parsed, (1, -1, 0))


if __name__ == "__main__":
    unittest.main()
