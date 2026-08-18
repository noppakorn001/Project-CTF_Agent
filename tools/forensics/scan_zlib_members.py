#!/usr/bin/env python3
"""Find bounded zlib members in a selected binary stream, without executing data."""
from __future__ import annotations

import argparse
import hashlib
import zlib
from pathlib import Path

MAGICS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")


def scan(data: bytes, max_members: int = 128, max_output: int = 8 << 20) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    seen: set[int] = set()
    for magic in MAGICS:
        start = 0
        while len(results) < max_members:
            offset = data.find(magic, start)
            if offset < 0:
                break
            start = offset + 1
            if offset in seen:
                continue
            seen.add(offset)
            dec = zlib.decompressobj()
            try:
                out = dec.decompress(data[offset:], max_output + 1)
                out += dec.flush()
            except zlib.error:
                continue
            if len(out) > max_output or not dec.eof:
                continue
            results.append({"offset": offset, "length": len(out), "sha256": hashlib.sha256(out).hexdigest()})
    return sorted(results, key=lambda item: int(item["offset"]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--max-input", type=int, default=256 << 20)
    ap.add_argument("--max-output", type=int, default=8 << 20)
    args = ap.parse_args()
    if args.input.stat().st_size > args.max_input:
        raise SystemExit("input cap exceeded")
    data = args.input.read_bytes()
    for row in scan(data, max_output=args.max_output):
        print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
