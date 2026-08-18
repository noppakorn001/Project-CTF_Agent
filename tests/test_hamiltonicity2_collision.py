import importlib
import json
import os
import sys
import unittest


SOLVER_MODULE = "2024_hamiltonicity2_collision_solve"
VERIFY_MODULE = "2024_hamiltonicity2_collision_verify"
SOLVER_PATH = "ctf_challenges/cryptohack_archive/solvers/2024_hamiltonicity2_collision_solve.py"
VERIFY_PATH = "ctf_challenges/cryptohack_archive/solvers/2024_hamiltonicity2_collision_verify.py"
TRANSCRIPT = "ctf_challenges/cryptohack_archive/files/2024/hamiltonicity_2-cryptohack202/live_collision_transcript.json"
FLAG = "crypto{ambiguous_hashing_encoding_ruins_RO_reduction}"


class Hamiltonicity2CollisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, "ctf_challenges/cryptohack_archive/solvers")
        cls.solver = importlib.import_module(SOLVER_MODULE)
        cls.verifier = importlib.import_module(VERIFY_MODULE)

    def test_branch_matrices_have_identical_hash_encoding(self):
        pair = self.solver.build_collision_pair()
        serialized0 = "".join(str(x) for row in pair.a0 for x in row)
        serialized1 = "".join(str(x) for row in pair.a1 for x in row)
        self.assertEqual(pair.serialized, serialized0)
        self.assertEqual(serialized0, serialized1)

    def test_transcript_uses_both_branches_and_128_bits(self):
        proofs, bits = self.solver.build_transcript()
        self.assertEqual(len(proofs), 128)
        self.assertEqual(len(bits), 128)
        self.assertIn("0", bits)
        self.assertIn("1", bits)
        self.assertEqual(sum(1 for bit, proof in zip(bits, proofs) if bit == "1" and len(proof["z"][0]) == 5), bits.count("1"))

    def test_live_record_is_independently_verified(self):
        if not os.path.exists(TRANSCRIPT):
            self.skipTest("live transcript is not present")
        self.verifier.verify(TRANSCRIPT, FLAG)

    def test_verifier_does_not_import_solver(self):
        with open(VERIFY_PATH, encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn("collision_solve", source)


if __name__ == "__main__":
    unittest.main()
