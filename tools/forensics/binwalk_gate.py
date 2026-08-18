#!/usr/bin/env python3
"""Run identification-only binwalk against one supplied artifact.

No extraction flag is accepted. The wrapper records size/hash and caps output so
it can be used during CTF triage without turning an archive into host files.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path


def run_identification(executable: str, artifact: Path, timeout: float = 30.0) -> tuple[int, str, str]:
    """Run only Binwalk's signature scan and cap diagnostic output."""

    if timeout <= 0 or timeout > 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    proc = subprocess.run(
        [executable, "--signature", str(artifact)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout[:20000], proc.stderr[:4000]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact", type=Path)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()
    if not args.artifact.is_file() or args.artifact.is_symlink():
        raise SystemExit("artifact must be a regular, non-symlink file")
    size = args.artifact.stat().st_size
    if size > 256 << 20:
        raise SystemExit("input cap exceeded")
    digest = hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    print(f"path={args.artifact} size={size} sha256={digest}")
    exe = shutil.which("binwalk")
    if exe is None:
        print("binwalk=unavailable (identification skipped)")
        return 0
    code, stdout, stderr = run_identification(exe, args.artifact, args.timeout)
    print(stdout, end="")
    if stderr:
        print(stderr, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
