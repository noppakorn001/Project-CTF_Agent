"""Opt-in Docker runner for bounded, read-only artifact inspection."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


DEFAULT_IMAGE = "ctf-agent-static:local"
MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 8

_STATIC_ACTIONS: dict[str, tuple[str, ...]] = {
    "identify": ("file", "--brief", "--mime", "/artifact/input"),
    "archive_list": ("unzip", "-Z", "-1", "/artifact/input"),
    "elf_headers": ("readelf", "--wide", "--file-header", "--program-headers", "/artifact/input"),
    "elf_symbols": ("readelf", "--wide", "--symbols", "--relocs", "/artifact/input"),
    "strings": ("strings", "--all", "--bytes=4", "/artifact/input"),
    "object_headers": ("objdump", "--file-headers", "--private-headers", "/artifact/input"),
}


class SandboxError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxResult:
    action: str
    artifact_sha256: str
    exit_code: int
    timed_out: bool
    output: str
    output_sha256: str
    output_truncated: bool
    image: str

    def as_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "artifact_sha256": self.artifact_sha256,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "output": self.output,
            "output_sha256": self.output_sha256,
            "output_truncated": self.output_truncated,
            "image": self.image,
        }


class DockerStaticSandbox:
    """Run only explicit static tools against one read-only workspace artifact."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        image: str = DEFAULT_IMAGE,
        docker_binary: str = "docker",
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.image = image
        self.docker_binary = docker_binary

    def inspect(
        self,
        artifact_path: str | Path,
        *,
        action: str,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        operator_approved: bool = False,
    ) -> SandboxResult:
        if not operator_approved:
            raise SandboxError("operator approval is required for sandbox inspection")
        if action not in _STATIC_ACTIONS:
            raise SandboxError("unsupported static sandbox action")
        if not 1 <= int(timeout_seconds) <= DEFAULT_TIMEOUT_SECONDS:
            raise SandboxError("timeout must be between 1 and 8 seconds")
        artifact = Path(artifact_path).resolve()
        try:
            artifact.relative_to(self.workspace_root)
        except ValueError as exc:
            raise SandboxError("artifact must remain inside the challenge workspace") from exc
        if not artifact.is_file():
            raise SandboxError("artifact does not exist")

        artifact_hash = _hash_file(artifact)
        command = [
            self.docker_binary,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "32",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--volume",
            f"{artifact}:/artifact/input:ro",
            "--workdir",
            "/work",
            self.image,
            *_STATIC_ACTIONS[action],
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=int(timeout_seconds),
            )
            raw_output = completed.stdout or b""
            timed_out = False
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            raw_output = exc.stdout or b""
            timed_out = True
            exit_code = 124
        truncated = len(raw_output) > MAX_OUTPUT_BYTES
        bounded = raw_output[:MAX_OUTPUT_BYTES]
        return SandboxResult(
            action=action,
            artifact_sha256=artifact_hash,
            exit_code=exit_code,
            timed_out=timed_out,
            output=bounded.decode("utf-8", errors="replace"),
            output_sha256=hashlib.sha256(raw_output).hexdigest(),
            output_truncated=truncated,
            image=self.image,
        )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
