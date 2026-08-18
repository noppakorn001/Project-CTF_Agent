import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOLVER = ROOT / "ctf_challenges/picoctf2021_crypto/double_des/solve.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("double_des_solver", SOLVER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DoubleDesSolverTests(unittest.TestCase):
    def test_key_format_is_bounded_and_padded(self):
        solver = load_solver()
        self.assertEqual(solver.candidate_key(0), b"000000  ")
        self.assertEqual(solver.candidate_key(999999), b"999999  ")

    def test_des_round_trip(self):
        solver = load_solver()
        des = solver.OpenSSLDes()
        key = solver.candidate_key(123456)
        block = b"ABCDEFG "
        encrypted = des.crypt(block, key)
        self.assertEqual(des.crypt(encrypted, key, decrypt=True), block)

    def test_meet_in_the_middle_replay(self):
        solver = load_solver()
        des = solver.OpenSSLDes()
        key1 = solver.candidate_key(123456)
        key2 = solver.candidate_key(654321)
        block = b"ABCDEFG "
        ciphertext = des.crypt(des.crypt(block, key1), key2)
        recovered = solver.meet_in_the_middle(des, ciphertext)
        # DES ignores each byte's parity bit, so several decimal spellings
        # represent the same effective key.  Verify the recovered pair by
        # replaying the block rather than requiring the original spelling.
        self.assertEqual(des.crypt(des.crypt(block, recovered.key1), recovered.key2), ciphertext)


if __name__ == "__main__":
    unittest.main()
