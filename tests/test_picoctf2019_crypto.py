import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "ctf_challenges/picoctf2019_crypto"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Pico2019CryptoTests(unittest.TestCase):
    def test_the_numbers_and_rot13(self):
        numbers = load(BASE / "the_numbers/solve.py", "pico19_numbers")
        thirteen = load(BASE / "thirteen/solve.py", "pico19_thirteen")
        self.assertEqual(
            numbers.decode_numbers("16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }"),
            "PICOCTF{THENUMBERSMASON}",
        )
        self.assertEqual(
            thirteen.solve("cvpbPGS{abg_gbb_onq_bs_n_ceboyrz}"),
            "picoCTF{not_too_bad_of_a_problem}",
        )

    def test_caesar_and_easy1(self):
        caesar = load(BASE / "caesar/solve.py", "pico19_caesar")
        easy1 = load(BASE / "easy1/solve.py", "pico19_easy1")
        candidates = caesar.solve("picoCTF{bqnrrhmfsgdqtahbnmphkgrwqj}")
        self.assertIn("picoCTF{crossingtherubiconqilhsxrk}", candidates)
        self.assertEqual(easy1.solve(), "CRYPTOISFUN")

    def test_mr_worldwide_and_morse(self):
        mr = load(BASE / "mr_worldwide/solve.py", "pico19_mr")
        tapping = load(BASE / "tapping/solve.py", "pico19_tapping")
        cities = "Kyoto Odesa Dayton Istanbul Abu_Dhabi Kuala_Lumpur _ Addis_Ababa Loja Amsterdam Sleepy_Hollow Kodiak Alexandria".split()
        self.assertEqual(mr.solve(cities), "KODIAK_ALASKA")
        morse = ".--. .. -.-. --- -.-. - ..-. { -- ----- .-. ... ...-- -.-. ----- -.. ...-- .---- ... ..-. ..- -. .---- ..--- -.... .---- ....- ...-- ---.. .---- ---.. .---- }"
        self.assertEqual(tapping.decode(morse), "PICOCTF{M0RS3C0D31SFUN1261438181}")

    def test_rsa_and_abc_primitives(self):
        mini = load(BASE / "mini_rsa/solve.py", "pico19_mini")
        rsa2 = load(BASE / "b00tl3g_rsa2/solve.py", "pico19_rsa2")
        abc = load(BASE / "aes_abc/solve.py", "pico19_abc")
        message = b"picoCTF{tiny}"
        m = int.from_bytes(message, "big")
        self.assertEqual(mini.recover(pow(m, 3), 3, 1 << 200), message)
        self.assertEqual(mini.parse("N: 17\ne: 3\nc: 8\n"), (8, 3, 17))
        p, q = 257, 263
        n = p * q
        d = 65_537
        e = pow(d, -1, (p - 1) * (q - 1))
        small_m = 42
        self.assertEqual(rsa2.recover(pow(small_m, e, n), n), small_m.to_bytes(1, "big"))
        self.assertEqual(rsa2.parse("c: 123\nn: 456\ne: 789\n"), (123, 456))
        iv = bytes(range(16))
        block = bytes(range(16, 32))
        chained = ((int.from_bytes(iv, "big") + int.from_bytes(block, "big")) % (1 << 128)).to_bytes(16, "big")
        self.assertEqual(abc.decrypt_body(iv + chained), iv + block)


if __name__ == "__main__":
    unittest.main()
