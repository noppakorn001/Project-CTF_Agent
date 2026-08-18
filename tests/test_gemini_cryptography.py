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


SOLVE = load(
    "gemini_crypto_solve",
    ROOT / "ctf_challenges/image_challenges/gemini_cryptography/solve.py",
)


class GeminiCryptographyTests(unittest.TestCase):
    def test_stream_decodes_to_format_conforming_flag(self) -> None:
        stream = (ROOT / "ctf_challenges/image_challenges/gemini_cryptography/stream.txt").read_text()
        self.assertEqual(SOLVE.decode_stream(stream), "flag{wtctt-dcode-master-2025}")


if __name__ == "__main__":
    unittest.main()
