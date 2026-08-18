import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
TRANSCRIPT = ROOT / "ctf_challenges/cryptohack_archive/files/2022/unbalanced-icc_athens2022/output.txt"
VERIFY = ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_unbalanced_verify.py"
FLAG = "ICC{unb4lanc3d_pr1m3s_0nly_m4k3_th1ngs_w0rs3}"


class UnbalancedVerifierTests(unittest.TestCase):
    def test_known_candidate_reencrypts(self):
        result = subprocess.run(
            [sys.executable, str(VERIFY), str(TRANSCRIPT), FLAG],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERIFIED:", result.stdout)

    def test_mutation_rejected(self):
        result = subprocess.run(
            [sys.executable, str(VERIFY), str(TRANSCRIPT), FLAG.replace("w0rs3", "w0rs4")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
