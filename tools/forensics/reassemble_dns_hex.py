#!/usr/bin/env python3
"""Reassemble hex DNS labels from a bounded TShark field export.

Input lines may be ``frame<TAB>name`` or just a DNS name.  The script never
captures packets, follows domains, or extracts arbitrary files; it validates an
exact suffix, a single hex label, and hard limits before writing bytes.
"""
from __future__ import annotations

import argparse
import binascii
import re
from pathlib import Path

HEX = re.compile(r"^[0-9a-fA-F]+$")


def reassemble(lines: list[str], suffix: str, max_records: int = 10000, max_bytes: int = 64 << 20) -> bytes:
    if not suffix or not suffix.startswith("."):
        raise ValueError("suffix must begin with a dot")
    chunks: list[tuple[int, str]] = []
    for ordinal, raw in enumerate(lines):
        if ordinal >= max_records:
            raise ValueError("record cap exceeded")
        text = raw.strip().rstrip(".")
        if not text:
            continue
        parts = text.split("\t", 1)
        if len(parts) == 2 and parts[0].isdigit():
            sequence, name = int(parts[0]), parts[1].rstrip(".")
        else:
            sequence, name = ordinal, text
        wanted = suffix.strip(".")
        if not name.lower().endswith(wanted.lower()):
            raise ValueError(f"unexpected DNS suffix at record {ordinal}")
        label = name[: -(len(wanted) + 1)] if name.lower().endswith("." + wanted.lower()) else ""
        if not label or "." in label or len(label) % 2 or not HEX.fullmatch(label):
            raise ValueError(f"invalid hex label at record {ordinal}")
        if sum(len(x) for _, x in chunks) + len(label) > max_bytes * 2:
            raise ValueError("output cap exceeded")
        chunks.append((sequence, label))
    chunks.sort(key=lambda item: item[0])
    encoded = "".join(label for _, label in chunks)
    if len(encoded) // 2 > max_bytes:
        raise ValueError("output cap exceeded")
    return binascii.unhexlify(encoded)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--suffix", required=True)
    ap.add_argument("--max-records", type=int, default=10000)
    ap.add_argument("--max-bytes", type=int, default=64 << 20)
    args = ap.parse_args()
    data = reassemble(args.input.read_text(encoding="ascii").splitlines(), args.suffix, args.max_records, args.max_bytes)
    args.output.write_bytes(data)
    print(f"wrote {len(data)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
