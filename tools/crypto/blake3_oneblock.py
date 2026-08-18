"""Dependency-free BLAKE3 hash for messages of at most one 64-byte block.

Authenticator's password/label/challenge input is 43--44 bytes, so this
small implementation is sufficient for its bounded search and verifier.  It
is intentionally kept separate from the general provider layer.
"""

from __future__ import annotations

import struct

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
MSG_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START = 1
CHUNK_END = 2
ROOT = 8
MASK32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _g(v: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    v[a] = (v[a] + v[b] + x) & MASK32
    v[d] = _rotr(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & MASK32
    v[b] = _rotr(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & MASK32
    v[d] = _rotr(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & MASK32
    v[b] = _rotr(v[b] ^ v[c], 7)


def compress(cv: tuple[int, ...], block_words: tuple[int, ...], counter: int, block_len: int, flags: int) -> tuple[int, ...]:
    if len(cv) != 8 or len(block_words) != 16:
        raise ValueError("BLAKE3 compression dimensions are invalid")
    v = list(cv) + list(IV[:4]) + [counter & MASK32, (counter >> 32) & MASK32, block_len, flags]
    schedule = list(range(16))
    for round_index in range(7):
        m = [block_words[index] for index in schedule]
        _g(v, 0, 4, 8, 12, m[0], m[1])
        _g(v, 1, 5, 9, 13, m[2], m[3])
        _g(v, 2, 6, 10, 14, m[4], m[5])
        _g(v, 3, 7, 11, 15, m[6], m[7])
        _g(v, 0, 5, 10, 15, m[8], m[9])
        _g(v, 1, 6, 11, 12, m[10], m[11])
        _g(v, 2, 7, 8, 13, m[12], m[13])
        _g(v, 3, 4, 9, 14, m[14], m[15])
        schedule = [schedule[index] for index in MSG_PERMUTATION]
    return tuple((v[index] ^ v[index + 8]) & MASK32 for index in range(8)) + tuple(
        (v[index + 8] ^ cv[index]) & MASK32 for index in range(8)
    )


def hash_one_block(data: bytes) -> bytes:
    """Hash ``data`` in unkeyed mode when ``len(data) <= 64``."""
    if len(data) > 64:
        raise ValueError("hash_one_block accepts at most 64 bytes")
    padded = data + b"\x00" * (64 - len(data))
    words = struct.unpack("<16I", padded)
    output = compress(IV, words, 0, len(data), CHUNK_START | CHUNK_END | ROOT)
    return struct.pack("<16I", *output)[:32]


__all__ = ["hash_one_block", "compress"]
