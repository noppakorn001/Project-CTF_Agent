from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SOLVER = ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_key_recovery_experiment.py"


def load_solver():
    spec = importlib.util.spec_from_file_location("dctf_key_recovery_experiment", SOLVER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load key-recovery experiment")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class KeyRecoverySolverTests(unittest.TestCase):
    def test_six_trails_recover_all_round_keys_offline(self) -> None:
        solver = load_solver()
        plaintext, trails, _ = solver.build_samples(seed=0xDCDC)
        key = bytes(range(16))
        ciphertext = b"".join(
            solver.encrypt(key, plaintext[offset : offset + 16])
            for offset in range(0, len(plaintext), 16)
        )
        self.assertEqual(solver.recover_round_keys(plaintext, ciphertext, trails), solver.keys(key))


if __name__ == "__main__":
    unittest.main()
