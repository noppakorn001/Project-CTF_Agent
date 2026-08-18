import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/play_nice/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("play_nice_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PlayNiceSolverTests(unittest.TestCase):
    def test_decrypts_instance_transcript(self):
        solver = load_solver()
        alphabet = "e5u3q678csvp02dho9aztjrmglkb1wfyinx4"
        ciphertext = "y365g4719hoa6htmcpvo8rluylaz6i"
        plaintext = "n5qewfvgod0r39zr8vqvvzk5lzmau4"
        self.assertEqual(solver.decrypt_string(ciphertext, alphabet), plaintext)
        self.assertEqual(solver.encrypt_string(plaintext, alphabet), ciphertext)

    def test_parse_banner_and_reject_bad_alphabet(self):
        solver = load_solver()
        banner = (
            b"Here is the alphabet: e5u3q678csvp02dho9aztjrmglkb1wfyinx4\n"
            b"Here is the encrypted message: y365g4719hoa6htmcpvo8rluylaz6i\n"
            b"What is the plaintext message?"
        )
        self.assertEqual(solver.parse_banner(banner)[1], "y365g4719hoa6htmcpvo8rluylaz6i")
        with self.assertRaises(ValueError):
            solver.decrypt_string("aa", "a" * 36)


if __name__ == "__main__":
    unittest.main()
