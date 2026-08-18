from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = load(
    "diffecient_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_diffecient_verify.py",
)


class DiffecientTests(unittest.TestCase):
    def test_universal_collision_and_independent_transcript(self) -> None:
        added = bytes.fromhex("bdd0c04b5c3995827482773b12acab35bdd0c04b5c3995827482773b12acab35")
        admin = bytes.fromhex("652fa0565c3946be7482773b12acab35652fa0565c3946be7482773b12acab35")
        self.assertNotEqual(added, admin)
        self.assertTrue(all(VERIFY.murmur3_x86_32(added, s) % VERIFY.M == VERIFY.murmur3_x86_32(admin, s) % VERIFY.M for s in range(47)))
        record = {
            "host": "archive.cryptohack.org",
            "port": 29201,
            "added_key": added.hex(),
            "admin_key": admin.hex(),
            "transcript_tail": "SEKAI{synthetic_diffecient}",
        }
        self.assertIsNone(VERIFY.verify(record, "SEKAI{synthetic_diffecient}"))


if __name__ == "__main__":
    unittest.main()
