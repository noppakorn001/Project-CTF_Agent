"""Small, deterministic CTF recipes shared by challenge workspaces.

These helpers intentionally do not contact a network or submit flags.  A recipe
only transforms bounded local data; challenge-specific scripts remain
responsible for preserving hashes and recording provenance.
"""

from __future__ import annotations

import base64
import hashlib
import math
import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, Sequence


FLAG_RE = re.compile(r"picoCTF\{[^\r\n{}]+\}")


def caesar(text: str, shift: int) -> str:
    """Apply a signed Caesar shift while preserving case and punctuation."""

    result: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(char)
    return "".join(result)


def atbash(text: str) -> str:
    """Apply the involutive Atbash substitution, preserving case."""

    result: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr(ord("z") - (ord(char) - ord("a"))))
        elif "A" <= char <= "Z":
            result.append(chr(ord("Z") - (ord(char) - ord("A"))))
        else:
            result.append(char)
    return "".join(result)


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt a repeating Vigenere key, advancing only over ASCII letters."""

    normalized_key = "".join(char for char in key.upper() if char.isascii() and char.isalpha())
    if not normalized_key:
        raise ValueError("key must contain at least one ASCII letter")
    result: list[str] = []
    key_index = 0
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(normalized_key[key_index % len(normalized_key)]) - ord("A")
            result.append(chr((ord(char) - base - shift) % 26 + base))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def xor_repeating(data: bytes, key: bytes) -> bytes:
    """XOR bounded data with a non-empty repeating key."""

    if not key:
        raise ValueError("key must not be empty")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def strict_b64_decode(text: str) -> bytes:
    """Decode one Base64 layer with strict validation and bounded whitespace."""

    compact = "".join(text.split())
    if not compact:
        raise ValueError("Base64 input must not be empty")
    return base64.b64decode(compact, validate=True)


def integer_nth_root(value: int, degree: int) -> int | None:
    """Return an exact non-negative integer root, or ``None``."""

    if value < 0 or degree < 2 or degree > 64:
        return None
    if value in (0, 1):
        return value
    high = 1 << ((value.bit_length() + degree - 1) // degree)
    low = 0
    while low <= high:
        middle = (low + high) // 2
        powered = middle**degree
        if powered == value:
            return middle
        if powered < value:
            low = middle + 1
        else:
            high = middle - 1
    return None


def rsa_low_exponent_recover(
    ciphertext: int,
    exponent: int,
    modulus: int,
    *,
    max_k: int = 10_000,
) -> bytes:
    """Recover an unpadded small-exponent RSA message under a finite lift cap.

    This helper intentionally does not assume a flag format.  Callers must
    verify the recovered bytes against the original RSA relation and challenge
    encoding before treating them as a candidate.
    """

    if (
        exponent < 2
        or exponent > 64
        or modulus <= 0
        or ciphertext < 0
        or max_k < 0
        or max_k > 1_000_000
    ):
        raise ValueError("invalid RSA recovery parameters")
    for k in range(max_k + 1):
        root = integer_nth_root(ciphertext + k * modulus, exponent)
        if root is not None:
            length = max(1, (root.bit_length() + 7) // 8)
            return root.to_bytes(length, "big")
    raise ValueError("no exact root within the declared k cap")


def gf128_multiply(left: int, right: int) -> int:
    """Multiply two 128-bit values in the GHASH field GF(2^128).

    The reduction polynomial is the one used by AES-GCM.  Inputs are treated
    as big-endian field elements; callers should not pass attacker-controlled
    values without first applying an explicit size cap.
    """

    if not 0 <= left < (1 << 128) or not 0 <= right < (1 << 128):
        raise ValueError("GF(2^128) operands must be 128-bit unsigned integers")
    result = 0
    value = right
    reduction = 0xE1000000000000000000000000000000
    for bit in range(128):
        if (left >> (127 - bit)) & 1:
            result ^= value
        value = (value >> 1) ^ (reduction if value & 1 else 0)
    return result


def ghash(h: bytes, blocks: Iterable[bytes]) -> bytes:
    """Compute bounded AES-GCM GHASH over complete 16-byte blocks."""

    if len(h) != 16:
        raise ValueError("GHASH hash subkey must be 16 bytes")
    accumulator = 0
    subkey = int.from_bytes(h, "big")
    count = 0
    for block in blocks:
        if len(block) != 16:
            raise ValueError("GHASH blocks must be exactly 16 bytes")
        count += 1
        if count > 1_000_000:
            raise ValueError("too many GHASH blocks")
        accumulator = gf128_multiply(accumulator ^ int.from_bytes(block, "big"), subkey)
    return accumulator.to_bytes(16, "big")


def lagrange_at_zero(shares: Sequence[tuple[int, int]], modulus: int) -> int:
    """Recover f(0) from bounded Shamir shares over a prime field."""

    if modulus <= 2 or len(shares) == 0 or len(shares) > 4096:
        raise ValueError("invalid share set or modulus")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("share x-coordinates must be unique")
    if any(not 0 <= x < modulus or not 0 <= y < modulus for x, y in shares):
        raise ValueError("shares must be reduced modulo the field")
    secret = 0
    for index, (x_i, y_i) in enumerate(shares):
        numerator = 1
        denominator = 1
        for other, (x_j, _) in enumerate(shares):
            if other == index:
                continue
            numerator = (numerator * (-x_j)) % modulus
            denominator = (denominator * (x_i - x_j)) % modulus
        try:
            weight = numerator * pow(denominator, -1, modulus) % modulus
        except ValueError as exc:
            raise ValueError("share coordinates are not invertible in the field") from exc
        secret = (secret + y_i * weight) % modulus
    return secret


def _undo_right_xor(value: int, shift: int) -> int:
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ (result >> shift)
    return result & 0xFFFFFFFF


def _undo_left_xor(value: int, shift: int, mask: int) -> int:
    result = value
    for _ in range(32 // shift + 1):
        result = value ^ ((result << shift) & mask & 0xFFFFFFFF)
    return result & 0xFFFFFFFF


def mt19937_untemper(output: int) -> int:
    """Reverse the MT19937 tempering transform for one 32-bit output."""

    if not 0 <= output < (1 << 32):
        raise ValueError("MT19937 output must be a 32-bit unsigned integer")
    value = _undo_right_xor(output, 18)
    value = _undo_left_xor(value, 15, 0xEFC60000)
    value = _undo_left_xor(value, 7, 0x9D2C5680)
    return _undo_right_xor(value, 11)


def recover_mt19937_state(outputs: Sequence[int]) -> tuple[int, ...]:
    """Recover one MT19937 state array from 624 consecutive full outputs."""

    if len(outputs) < 624:
        raise ValueError("624 consecutive outputs are required")
    if any(not 0 <= value < (1 << 32) for value in outputs[:624]):
        raise ValueError("MT19937 outputs must be 32-bit unsigned integers")
    return tuple(mt19937_untemper(value) for value in outputs[:624])


def flag_candidates(values: Sequence[str]) -> list[str]:
    """Return unique whole-string picoCTF candidates from bounded values."""

    return list(dict.fromkeys(value for value in values if FLAG_RE.fullmatch(value)))


def sha256_file(path: os.PathLike[str] | str) -> str:
    """Hash a local artifact in bounded chunks without changing it."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_steghide_empty_passphrase(
    image: os.PathLike[str] | str,
    output: os.PathLike[str] | str,
    *,
    timeout_seconds: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    """Extract one payload using steghide's empty-passphrase path.

    The command is argv-based (no shell), writes only to ``output``, and is
    bounded by a timeout.  It raises ``FileNotFoundError`` when steghide is not
    installed so callers can report an honest, reproducible prerequisite.
    """

    image_path = Path(image).resolve()
    output_path = Path(output).resolve()
    if not image_path.is_file():
        raise FileNotFoundError(f"image does not exist: {image_path}")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if image_path == output_path:
        raise ValueError("output must not overwrite the source image")
    if output_path.is_symlink():
        raise ValueError("refusing to write through an output symlink")
    return subprocess.run(
        [
            "steghide",
            "extract",
            "-sf",
            str(image_path),
            "-p",
            "",
            "-xf",
            str(output_path),
            "-f",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
