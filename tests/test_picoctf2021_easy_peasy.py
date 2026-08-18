import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/easy_peasy/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("easy_peasy_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class EasyPeasySolverTests(unittest.TestCase):
    def test_recover_known_plaintext_xor(self):
        solver = load_solver()
        body = b"abc3c985f19f8227c0944d0fbd1c17ad"
        key = bytes(range(len(body)))
        encrypted_flag = bytes(a ^ b for a, b in zip(body, key))
        known_ciphertext = bytes(a ^ ord("A") for a in key)
        self.assertEqual(solver.recover_flag(encrypted_flag, known_ciphertext), body.decode())

    def test_wrap_length(self):
        solver = load_solver()
        self.assertEqual(solver.KEY_LEN - 32, 49_968)


if __name__ == "__main__":
    unittest.main()
