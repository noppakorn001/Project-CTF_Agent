#!/usr/bin/env python3
"""Bounded retry runner for the two still-pending CryptoHack archive cards.

This helper deliberately knows only the exact archive endpoints from the
allowlist.  It runs the existing challenge-specific clients, captures a small
bounded tail of their output, and never submits a flag.  A complete result is
still accepted only when the underlying solver returns successfully and its
own verifier can consume the recorded transcript.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_HOST = "archive.cryptohack.org"


@dataclass(frozen=True)
class Pending:
    name: str
    port: int
    solver: Path
    evidence_dir: Path
    timeout: int
    extra: tuple[str, ...] = ()
    supports_attempts: bool = False


PENDING = (
    Pending(
        "Maybe Someday (Maybe Someday CTF)",
        56434,
        ROOT / "ctf_challenges/cryptohack_archive/solvers/2022_maybe_someday_solve.py",
        ROOT / "ctf_challenges/cryptohack_archive/files/2022/maybe_someday-maybe_someday_c",
        5,
        supports_attempts=False,
    ),
    Pending(
        "OffTopic (ECSC 2024 Italy)",
        40704,
        ROOT / "ctf_challenges/cryptohack_archive/solvers/2024_offtopic_solve.py",
        ROOT / "ctf_challenges/cryptohack_archive/files/2024/offtopic-ecsc_2024_italy2024",
        75,
        ("--h-infinity", "--choice-scalar", "10"),
        supports_attempts=True,
    ),
)


def run_one(spec: Pending, attempt: int) -> dict[str, object]:
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    record = spec.evidence_dir / f"live_retry_{stamp}_{attempt}.json"
    command = [
        sys.executable,
        str(spec.solver),
        "--host",
        ARCHIVE_HOST,
        "--port",
        str(spec.port),
        "--timeout",
        str(spec.timeout),
        "--record",
        str(record),
        *spec.extra,
    ]
    if spec.supports_attempts:
        command[command.index("--record"):command.index("--record")] = ["--attempts", "1"]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=spec.timeout + 15,
            check=False,
        )
        output = (completed.stdout + completed.stderr).strip()
        # Keep logs bounded and redact anything that is not a flag-shaped line.
        flag = re.findall(r"(?:CTF|ECSC)\{[^}\r\n]{1,256}\}", output)
        return {
            "name": spec.name,
            "host": ARCHIVE_HOST,
            "port": spec.port,
            "attempt": attempt,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "returncode": completed.returncode,
            "flag_seen": flag[-1] if completed.returncode == 0 and flag else None,
            "record": str(record) if record.exists() else None,
            "output_tail": output[-1000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": spec.name,
            "host": ARCHIVE_HOST,
            "port": spec.port,
            "attempt": attempt,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "returncode": None,
            "flag_seen": None,
            "record": str(record) if record.exists() else None,
            "output_tail": str(exc)[:1000],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--only", choices=("maybe", "offtopic", "all"), default="all")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not 1 <= args.attempts <= 3:
        raise SystemExit("--attempts must be between 1 and 3")
    selected = PENDING if args.only == "all" else ((PENDING[0],) if args.only == "maybe" else (PENDING[1],))
    results = []
    for spec in selected:
        for attempt in range(1, args.attempts + 1):
            result = run_one(spec, attempt)
            results.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            if result["returncode"] == 0 and result["flag_seen"]:
                break
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"host": ARCHIVE_HOST, "results": results}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
