import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/scrambled_rsa/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("scrambled_rsa_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScrambledRsaSolverTests(unittest.TestCase):
    def test_parse_banner_and_remove_duplicate_segments(self):
        solver = load_solver()
        banner = (
            b"flag: 123456789\n"
            b"n: 99991\n"
            b"e: 65537\n"
            b"I will encrypt whatever you give me: "
        )
        encrypted, modulus, exponent = solver.parse_banner(banner)
        self.assertEqual((encrypted, modulus, exponent), ("123456789", 99991, 65537))
        self.assertEqual(solver.remove_known("aaab", ["a", "a", "a", "b"]), "")

    def test_response_validation(self):
        solver = load_solver()
        self.assertEqual(solver.response_value(b"Here you go: 123\n"), "123")
        with self.assertRaises(ValueError):
            solver.response_value(b"Here you go: nope\n")

    def test_final_line_segment_is_allowed_but_large_remainder_is_not(self):
        solver = load_solver()
        modulus, exponent = 99991, 3
        solver.verify_flag_segments("1234567", ["123"], modulus, exponent)
        with self.assertRaises(ValueError):
            solver.verify_flag_segments("123456789", ["123"], modulus, exponent)


if __name__ == "__main__":
    unittest.main()
