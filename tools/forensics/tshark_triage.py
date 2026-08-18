#!/usr/bin/env python3
"""Run bounded, offline TShark triage against one supplied capture.

The wrapper intentionally accepts only ``-r``/display-filter style operations.
It never opens a live interface, writes a capture, follows a stream, or exports
unbounded packet payloads.  The printed header gives a provenance anchor for a
later evidence timeline; the selected rows are a lead until tied back to frame
numbers and the original capture hash.
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path


DEFAULT_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "_ws.col.Protocol",
    "ip.src",
    "ip.dst",
    "tcp.stream",
    "_ws.col.Info",
)


def _run(
    executable: str,
    artifact: Path,
    *,
    display_filter: str | None,
    fields: tuple[str, ...],
    timeout: float,
    output_cap: int,
) -> tuple[int, str, str]:
    """Run a read-only field export and cap both decoded output streams."""

    if timeout <= 0 or timeout > 300:
        raise ValueError("timeout must be between 0 and 300 seconds")
    if output_cap <= 0 or output_cap > 64 << 20:
        raise ValueError("output cap is outside safe bounds")
    command = [executable, "-r", str(artifact), "-T", "fields", "-E", "header=n"]
    for field in fields:
        if not field or field.startswith("-") or any(ch.isspace() for ch in field):
            raise ValueError(f"unsafe field name: {field!r}")
        command.extend(("-e", field))
    if display_filter:
        if len(display_filter) > 1024 or "\x00" in display_filter:
            raise ValueError("display filter is too long or contains NUL")
        command.extend(("-Y", display_filter))
    # This is an argv list, not a shell command.  In particular, no -i/-f/-w
    # options are accepted here: capture belongs outside the artifact workflow.
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    stdout = proc.stdout[:output_cap]
    stderr = proc.stderr[: min(output_cap, 16 << 10)]
    return proc.returncode, stdout, stderr


def triage(
    artifact: Path,
    *,
    display_filter: str | None = None,
    fields: tuple[str, ...] = DEFAULT_FIELDS,
    timeout: float = 30.0,
    output_cap: int = 2 << 20,
) -> dict[str, object]:
    """Return provenance plus an optional TShark field export."""

    artifact = artifact.resolve()
    if not artifact.is_file() or artifact.is_symlink():
        raise ValueError("capture must be a regular, non-symlink file")
    size = artifact.stat().st_size
    if size > 256 << 20:
        raise ValueError("capture input cap exceeded")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    result: dict[str, object] = {
        "path": str(artifact),
        "size": size,
        "sha256": digest,
        "display_filter": display_filter or "",
        "fields": list(fields),
    }
    executable = shutil.which("tshark")
    if executable is None:
        result.update({"available": False, "returncode": None, "stdout": "", "stderr": "tshark unavailable"})
        return result
    code, stdout, stderr = _run(
        executable,
        artifact,
        display_filter=display_filter,
        fields=fields,
        timeout=timeout,
        output_cap=output_cap,
    )
    result.update({"available": True, "returncode": code, "stdout": stdout, "stderr": stderr})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--filter", dest="display_filter", help="bounded TShark display filter")
    parser.add_argument("--field", action="append", dest="fields", help="field to export; repeatable")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--max-output", type=int, default=2 << 20)
    args = parser.parse_args()
    fields = tuple(args.fields) if args.fields else DEFAULT_FIELDS
    report = triage(
        args.capture,
        display_filter=args.display_filter,
        fields=fields,
        timeout=args.timeout,
        output_cap=args.max_output,
    )
    print(f"path={report['path']} size={report['size']} sha256={report['sha256']}")
    if not report["available"]:
        print("tshark=unavailable (offline triage skipped)")
        return 0
    print(f"tshark_returncode={report['returncode']}")
    stdout = str(report["stdout"])
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    stderr = str(report["stderr"])
    if stderr:
        print(stderr, end="" if stderr.endswith("\n") else "\n")
    return int(report["returncode"])


if __name__ == "__main__":
    raise SystemExit(main())
