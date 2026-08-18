from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOLVER = load(
    "authenticator_solver",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_authenticator_solve.py",
)


class AuthenticatorSolverTests(unittest.TestCase):
    def test_bounded_blake3_fallback_matches_reference_vector(self) -> None:
        self.assertEqual(
            SOLVER._blake3(b"").hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )

    def test_unrank_matches_permutation_order_for_small_prefix(self) -> None:
        import itertools

        expected = list(itertools.islice(itertools.permutations(SOLVER.ALPHABET, SOLVER.PASSWORD_LENGTH), 1001))
        for rank in (0, 1, 2, 1000):
            self.assertEqual(SOLVER.unrank_permutation(rank), bytes(expected[rank]))

    def test_shard_is_bounded_and_disjoint(self) -> None:
        left = list(SOLVER.iter_shard(0, 2, 3))
        right = list(SOLVER.iter_shard(1, 2, 3))
        self.assertEqual(len(left), 3)
        self.assertEqual(len(right), 3)
        self.assertTrue(set(rank for rank, _ in left).isdisjoint(rank for rank, _ in right))

    def test_host_and_port_are_exact(self) -> None:
        with self.assertRaises(ValueError):
            SOLVER.solve(host="example.invalid", port=40156, max_candidates=1)
        with self.assertRaises(ValueError):
            SOLVER.solve(host=SOLVER.HOST, port=40157, max_candidates=1)

    def test_direct_rank_table_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "table.bin"
            path.write_bytes(b"\x01\x02\xaa\xbb\x01\x02")
            self.assertEqual(SOLVER.table_matches(path, b"\x01\x02", prefix_bytes=2, start_rank=40), [40, 42])


if __name__ == "__main__":
    unittest.main()
