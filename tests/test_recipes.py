import tempfile
import unittest
from pathlib import Path

from ctf_agent.recipes import (
    atbash,
    caesar,
    flag_candidates,
    gf128_multiply,
    ghash,
    integer_nth_root,
    lagrange_at_zero,
    mt19937_untemper,
    recover_mt19937_state,
    rsa_low_exponent_recover,
    sha256_file,
    strict_b64_decode,
    vigenere_decrypt,
    xor_repeating,
)


class RecipeTests(unittest.TestCase):
    def test_caesar_and_atbash(self):
        self.assertEqual(caesar("xqkwKBN{z0bib1wv}", -8), "picoCTF{r0tat1on}")
        encrypted = "krxlXGU{zgyzhs_xizxp_xz00558y}"
        self.assertEqual(atbash(encrypted), "picoCTF{atbash_crack_ca00558b}")
        self.assertEqual(atbash(atbash(encrypted)), encrypted)

    def test_flag_candidates_are_whole_and_unique(self):
        self.assertEqual(
            flag_candidates(["picoCTF{ok}", "noise picoCTF{no}", "picoCTF{ok}"]),
            ["picoCTF{ok}"],
        )

    def test_sha256_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "artifact"
            path.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_reusable_crypto_transforms(self):
        self.assertEqual(vigenere_decrypt("LXFOPV EF RNHR", "LEMON"), "ATTACK AT DAWN")
        self.assertEqual(xor_repeating(b"\x00\x01\x02\x03", b"\xff\x01"), b"\xff\x00\xfd\x02")
        self.assertEqual(strict_b64_decode("cGljb0NURntva30="), b"picoCTF{ok}")
        self.assertIsNone(integer_nth_root(10, 3))
        message = b"picoCTF{root}"
        exponent = 3
        plaintext = int.from_bytes(message, "big")
        ciphertext = plaintext**exponent
        self.assertEqual(
            rsa_low_exponent_recover(ciphertext, exponent, 1 << 256),
            message,
        )

    def test_archive_crypto_recipes(self):
        self.assertEqual(
            gf128_multiply(
                0x0388DACE60B6A392F328C2B971B2FE78,
                0x66E94BD4EF8A2C3B884CFA59CA342B2E,
            ),
            0x5E2EC746917062882C85B0685353DEB7,
        )
        self.assertEqual(
            ghash(
                bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"),
                [bytes.fromhex("0388dace60b6a392f328c2b971b2fe78")],
            ),
            bytes.fromhex("5e2ec746917062882c85b0685353deb7"),
        )
        shares = [(1, 15), (2, 41), (3, 81)]
        self.assertEqual(lagrange_at_zero(shares, 101), 3)

        def temper(value: int) -> int:
            value ^= value >> 11
            value ^= (value << 7) & 0x9D2C5680
            value ^= (value << 15) & 0xEFC60000
            value ^= value >> 18
            return value & 0xFFFFFFFF

        state = tuple((index * 0x12345 + 7) & 0xFFFFFFFF for index in range(624))
        outputs = [temper(value) for value in state]
        self.assertEqual(mt19937_untemper(outputs[17]), state[17])
        self.assertEqual(recover_mt19937_state(outputs), state)
