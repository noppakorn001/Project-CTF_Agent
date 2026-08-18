import importlib.util
import sys
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/compress_and_attack/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("compress_attack_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CompressAttackTests(unittest.TestCase):
    def test_choose_minima_keeps_ties(self):
        solver = load_solver()
        self.assertEqual(solver.choose_minima(["a", "b", "c"], [4, 2, 2]), ["b", "c"])

    def test_local_zlib_oracle_recovers_prefix_progress(self):
        solver = load_solver()
        flag = "picoCTF{sheriff_you_solved_the_crime}"
        payloads = ["picoCTF{" + char for char in solver.ALPHABET]
        lengths = [len(zlib.compress((flag + payload).encode())) for payload in payloads]
        self.assertEqual(solver.choose_minima(payloads, lengths), ["picoCTF{s"])


if __name__ == "__main__":
    unittest.main()
