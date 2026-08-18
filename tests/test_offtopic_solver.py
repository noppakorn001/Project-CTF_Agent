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


SOLVE = load(
    "offtopic_solve",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2024_offtopic_solve.py",
)


class OffTopicTests(unittest.TestCase):
    def test_json_parser_accepts_prompt_prefixed_response(self) -> None:
        class FakeReader:
            def __init__(self):
                self.lines = [b"Send your encrypted choice bit: {\"Rx\":1,\"Ry\":2}\n"]

            def readline(self):
                return self.lines.pop(0) if self.lines else b""

        self.assertEqual(
            SOLVE.read_json_line(FakeReader()),
            {"Rx": 1, "Ry": 2},
        )

    def test_bounded_table_includes_point_at_infinity(self) -> None:
        table = {}
        choice_scalar = 10
        for m0 in range(10):
            for m1 in range(10):
                point = SOLVE.mul((1 - choice_scalar) * m0 + choice_scalar * m1)
                self.assertNotIn(point, table, (m0, m1))
                table[point] = (m0, m1)
        self.assertEqual(table[None], (0, 0))
        self.assertEqual(SOLVE.decode_pair(None, table), (0, 0))
        self.assertEqual(SOLVE.decode_pair((0, 0), table), (0, 0))
        self.assertEqual(len(table), 100)


if __name__ == "__main__":
    unittest.main()
