from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOLVER = load("maybe_solver", ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_maybe_someday_solve.py")
VERIFY = load("maybe_verify", ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_maybe_someday_verify.py")


class MaybeSomedayTests(unittest.TestCase):
    def test_nonadaptive_partitions_recover_a_unique_candidate(self) -> None:
        pool = SOLVER.candidates()
        queries, partitions = SOLVER.generate_queries(pool)
        self.assertEqual(len(queries), 20)
        candidate = pool[12345]
        responses = [candidate in valid for _, valid in partitions]
        intersection = set(pool)
        for index, response in enumerate(responses):
            intersection &= partitions[index][int(response)]
        self.assertIn(candidate, intersection)
        self.assertLessEqual(len(intersection), 3)

    def test_independent_transcript_intersections(self) -> None:
        pool = SOLVER.candidates()
        _, partitions = VERIFY.generate_queries(pool)
        candidate = pool[54321]
        responses = [candidate in valid for _, valid in partitions]
        record = {
            "host": "archive.cryptohack.org",
            "port": 56434,
            "queries": [[list(item) for item in query] for query in SOLVER.generate_queries(pool)[0]],
            "rounds": [
                {"c0": 1, "responses": responses, "secret": candidate.decode()}
                for _ in range(16)
            ],
            "flag": "CTF{synthetic_nonadaptive_oracle}",
        }
        self.assertEqual(VERIFY.verify(record), record["flag"])


if __name__ == "__main__":
    unittest.main()
