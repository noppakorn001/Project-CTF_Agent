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
    "pekobot_verify",
    ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_pekobot_verify.py",
)


class PekobotTests(unittest.TestCase):
    def test_independent_curve_transcript_verification(self) -> None:
        # NIST P-256 generator; this test is entirely offline.
        point = (
            48439561293906451759052585252797914202762949526041747995844080717082404635286,
            36134250956749795798585127919587881956611106672985015071877198253568414405109,
        )
        key = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        quote = "ok peko"
        encrypted_quote = bytes(
            a ^ b for a, b in zip(key, quote.encode().ljust(64, b"\0"))
        )
        flag = b"AIS3{synthetic_replay}"
        c2 = bytes(a ^ b for a, b in zip(key, flag.ljust(64, b"\0")))
        record = {
            "host": "archive.cryptohack.org",
            "port": 45328,
            "c2": c2.hex(),
            "encrypted_quote": encrypted_quote.hex(),
            "candidates": [{"quote": quote, "point": list(point)}],
        }
        self.assertIsNone(VERIFY.verify(record, flag.decode()))


if __name__ == "__main__":
    unittest.main()
