import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_c0ll1d3r_solve.py"
SPEC = importlib.util.spec_from_file_location("c0ll1d3r_solver", PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
VERIFY_PATH = ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_c0ll1d3r_verify.py"
VERIFY_SPEC = importlib.util.spec_from_file_location("c0ll1d3r_verify", VERIFY_PATH)
assert VERIFY_SPEC and VERIFY_SPEC.loader
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


class C0ll1d3rMathTests(unittest.TestCase):
    def test_consecutive_hash_gcd_recovers_prime(self):
        p = 2**256 - 189
        g = 1337
        hashes = [
            pow(g, int.from_bytes(MODULE.PREFIX + message, "big"), p).to_bytes(32, "big")
            for message in (b"a", b"b", b"c", b"d")
        ]
        self.assertTrue(MODULE.is_probable_prime(p))
        self.assertEqual(MODULE.recover_prime(hashes), p)

    def test_lattice_shape_and_centered_congruence(self):
        p = 2**256 - 189
        rows = MODULE._matrix(p, 12)
        self.assertEqual(len(rows), 14)
        self.assertTrue(all(len(row) == 14 for row in rows))
        # The first row's constant is the centered base-256 residue; the
        # modulus row is present and carries the same documented weight.
        self.assertEqual(rows[-1][0] % 256, ((p - 1) * 256) % 256)
        self.assertEqual(rows[0][1], 1)

    def test_recorded_live_replay_independent_verifier(self):
        record = ROOT / "ctf_challenges/cryptohack_archive/files/2022/c0ll1d3r-firebird_internal_ct/live_replay.json"
        self.assertTrue(record.exists())
        self.assertEqual(
            VERIFY.verify(record),
            "firebird{wh3n_1n_d0ub7_u5e_latt111c3_r3duc71110n_4lg0r111thm}",
        )


if __name__ == "__main__":
    unittest.main()
