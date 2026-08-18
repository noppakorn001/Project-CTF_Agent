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


SOLVER = load(
    "numpy_mt_solver",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2021_import_numpy_as_mt_solve.py",
)
VERIFY = load(
    "numpy_mt_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2021_import_numpy_as_mt_verify.py",
)


class NumpyMtSolverTests(unittest.TestCase):
    def test_seed_zero_matches_reference_mt_bytes(self) -> None:
        self.assertEqual(SOLVER.mt_bytes(0).hex(), "ac0a7f8c2faac49775a616b7c0cc21d8")

    def test_independent_reencryption_verifier(self) -> None:
        candidate = "zh3r0{synthetic_numpy_mt_replay}"
        outer_seed, inner_seed = 654321, 123456
        outer_iv, outer_key = SOLVER.mt_bytes(outer_seed), SOLVER.mt_bytes(outer_seed, 32)[16:]
        inner_iv, inner_key = SOLVER.mt_bytes(inner_seed), SOLVER.mt_bytes(inner_seed, 32)[16:]
        payload = candidate.encode()
        padding = 16 - len(payload) % 16
        payload += bytes([padding]) * padding
        inner = inner_iv + VERIFY.aes_cbc_encrypt(inner_iv, inner_key, payload)
        ciphertext = outer_iv + VERIFY.aes_cbc_encrypt(outer_iv, outer_key, inner)
        VERIFY.verify(
            {
                "host": "archive.cryptohack.org",
                "port": 7265,
                "outer_seed": outer_seed,
                "inner_seed": inner_seed,
                "ciphertext": ciphertext.hex(),
            },
            candidate,
        )


if __name__ == "__main__":
    unittest.main()
