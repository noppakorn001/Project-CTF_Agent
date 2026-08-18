"""Bounded diagnostic for C0ll1d3r's first LLL length; no fifth query."""
from __future__ import annotations

import socket
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ctf_challenges/cryptohack_archive/solvers"))
import importlib.util

spec = importlib.util.spec_from_file_location("c0", Path(sys.path[0]) / "2022_c0ll1d3r_solve.py")
assert spec and spec.loader
c0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c0)

with socket.create_connection((c0.HOST, c0.PORT), timeout=20) as sock:
    sock.settimeout(120)
    hs = []
    for m in (b"a", b"b", b"c", b"d"):
        sock.sendall(m + b"\n")
        hs.append(c0._read_hash(sock))
    p = c0.recover_prime(hs)
    print("p_bits", p.bit_length(), "p", p)
    rows = c0._lll(c0._matrix(p, 100), precision=256, backend="fast")
    hits = sorted((abs(row[1]), row[0], row[1], min(row[2:]), max(row[2:])) for row in rows if row[0] == 0)
    print("zero_rows", len(hits))
    for row in hits[:20]:
        print(row)
    print("unit_rows")
    for row in hits:
        if abs(row[2]) == 1:
            print(row)
    candidate = c0._candidate_from_rows(rows, p, 100)
    if candidate is not None:
        print("candidate", candidate)
        sock.sendall(candidate + b"\n")
        data = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        print(bytes(data).decode(errors="replace"))
    else:
        print("no validated length-100 candidate; fifth query was not sent")
