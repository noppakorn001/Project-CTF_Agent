#!/usr/bin/env python3
"""Conservative PreToolUse guard for Bash commands in the CTF workspace.

The hook intentionally blocks only clearly destructive, privileged, secret-reading,
or out-of-scope operations. It does not attempt to prove that arbitrary shell code is
safe and must be paired with a disposable VM and Codex sandboxing.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import sys
from pathlib import Path
from urllib.parse import urlsplit


MAX_COMMAND_CHARS = 100_000
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")"}
REDIRECTS = {">", ">>", "<>", ">|"}
LOCAL_TARGETS = {"localhost", "127.0.0.1", "::1"}

ALWAYS_DENY = {
    "sudo",
    "doas",
    "pkexec",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "telinit",
    "systemctl",
    "service",
    "mount",
    "umount",
    "nsenter",
    "chroot",
    "swapon",
    "swapoff",
    "kexec",
    "wipefs",
    "fdisk",
    "sfdisk",
    "parted",
    "cryptsetup",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "groupdel",
    "groupmod",
    "passwd",
    "chpasswd",
    "visudo",
    "iptables",
    "ip6tables",
    "nft",
    "ufw",
    "firewall-cmd",
    "apt",
    "apt-get",
    "dpkg",
    "dnf",
    "yum",
    "pacman",
    "zypper",
    "snap",
    "eval",
}

NETWORK_COMMANDS = {
    "curl",
    "wget",
    "ssh",
    "scp",
    "sftp",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "nmap",
    "masscan",
    "hydra",
    "dig",
    "host",
    "nslookup",
}

SENSITIVE_PATH = re.compile(
    r"(?:^|[\s/])(?:"
    r"\.ssh|\.aws|\.gnupg|\.kube|\.docker/config\.json|"
    r"\.config/gcloud|\.config/gh/hosts\.yml"
    r")(?:/|$)|"
    r"/(?:etc/(?:shadow|gshadow|sudoers)(?:\.d)?|proc/(?:self|[0-9]+)/environ)(?:/|$)",
    re.IGNORECASE,
)


def deny(reason: str) -> None:
    """Return the current Codex PreToolUse denial schema on stdout."""

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")


def repo_root(cwd: Path) -> Path:
    """Find the repository boundary without invoking another command."""

    current = cwd.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


def strip_heredoc_bodies(command: str) -> tuple[str, bool, str | None]:
    """Remove here-doc data so quoted examples are not parsed as shell commands."""

    lines = command.splitlines()
    kept: list[str] = []
    delimiter: str | None = None
    owner: str | None = None
    saw_heredoc = False
    pattern = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
    for line in lines:
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        kept.append(line)
        match = pattern.search(line)
        if match:
            saw_heredoc = True
            delimiter = match.group(2)
            try:
                owner = shlex.split(line, comments=False, posix=True)[0]
            except (ValueError, IndexError):
                owner = None
    return "\n".join(kept), saw_heredoc, owner


def delimit_unquoted_newlines(command: str) -> str:
    """Turn actual shell newlines into command separators while preserving quotes."""

    result: list[str] = []
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            result.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            result.append(char)
            escaped = True
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            result.append(char)
            continue
        result.append(";" if char == "\n" and quote is None else char)
    return "".join(result)


def shell_tokens(command: str) -> list[str]:
    lexer = shlex.shlex(
        delimit_unquoted_newlines(command),
        posix=True,
        punctuation_chars=";&|()<>",
    )
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def split_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token in SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(token)
    if current:
        segments.append(current)
    return segments


def executable_and_args(segment: list[str]) -> tuple[str, list[str]]:
    """Return the executable position, ignoring assignments and redirections."""

    cleaned: list[str] = []
    skip_next = False
    for token in segment:
        if skip_next:
            skip_next = False
            continue
        if token in {"<", "<<", "<<<"}:
            skip_next = True
            continue
        if token in REDIRECTS:
            skip_next = True
            continue
        cleaned.append(token)
    while cleaned and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", cleaned[0], re.DOTALL):
        cleaned.pop(0)
    if not cleaned:
        return "", []
    executable = Path(cleaned[0]).name
    return executable, cleaned[1:]


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_shell_path(token: str, cwd: Path) -> Path | None:
    if not token or token == "-" or token.startswith("-"):
        return None
    if token.startswith(("$", "`")) or "$" in token:
        return None
    try:
        path = Path(token).expanduser()
        return (path if path.is_absolute() else cwd / path).resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def unsafe_write_path(token: str, *, cwd: Path, root: Path) -> bool:
    if token in {"/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}"}:
        return True
    resolved = resolve_shell_path(token, cwd)
    return resolved is None or not is_within(resolved, root)


def redirection_violation(segment: list[str], *, cwd: Path, root: Path) -> bool:
    for index, token in enumerate(segment[:-1]):
        if token in REDIRECTS and unsafe_write_path(segment[index + 1], cwd=cwd, root=root):
            return True
    return False


def sensitive_path_violation(executable: str, args: list[str]) -> bool:
    """Detect actual sensitive-path operands while allowing quoted search patterns."""

    if not any(SENSITIVE_PATH.search(token) for token in args):
        return False
    if executable in {"echo", "printf"}:
        return False

    if executable in {"rg", "grep", "egrep", "fgrep"}:
        path_operands: list[str] = []
        positional: list[str] = []
        explicit_pattern = False
        consume: str | None = None
        value_options = {
            "-g",
            "--glob",
            "--iglob",
            "-t",
            "--type",
            "-T",
            "--type-not",
            "--type-add",
            "-m",
            "--max-count",
            "--max-depth",
            "--sort",
            "--sortr",
            "-r",
            "--replace",
            "-A",
            "-B",
            "-C",
            "--after-context",
            "--before-context",
            "--context",
        }
        for token in args:
            if consume is not None:
                if consume == "path":
                    path_operands.append(token)
                consume = None
                continue
            if token in {"-e", "--regexp"}:
                explicit_pattern = True
                consume = "pattern"
                continue
            if token in {"-f", "--file"}:
                explicit_pattern = True
                consume = "path"
                continue
            if token in value_options:
                consume = "value"
                continue
            if token.startswith("-"):
                continue
            positional.append(token)
        path_operands.extend(positional if explicit_pattern else positional[1:])
        return any(SENSITIVE_PATH.search(token) for token in path_operands)

    if executable in {"sed", "awk", "gawk", "mawk"}:
        path_operands: list[str] = []
        positional: list[str] = []
        explicit_program = False
        consume: str | None = None
        for token in args:
            if consume is not None:
                if consume == "path":
                    path_operands.append(token)
                consume = None
                continue
            if token in {"-e", "--expression"}:
                explicit_program = True
                consume = "program"
                continue
            if token in {"-f", "--file"}:
                explicit_program = True
                consume = "path"
                continue
            if token.startswith(("--expression=", "--file=")):
                explicit_program = True
                if token.startswith("--file="):
                    path_operands.append(token.split("=", 1)[1])
                continue
            if token.startswith("-"):
                continue
            positional.append(token)
        path_operands.extend(positional if explicit_program else positional[1:])
        return any(SENSITIVE_PATH.search(token) for token in path_operands)

    return True


def allowed_patterns() -> list[str]:
    raw = os.environ.get("CTF_AGENT_ALLOWED_TARGETS", "")
    result: list[str] = []
    for item in raw.split(","):
        value = item.strip().lower().rstrip(".")
        if not value or value in {"*", "*.*", "0.0.0.0/0", "::/0"}:
            continue
        if "/" in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue
            if network.num_addresses <= 65_536:
                result.append(str(network))
            continue
        if value.startswith("*."):
            base = value[2:]
            if "." in base and re.fullmatch(
                r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", base
            ):
                result.append(value)
            continue
        try:
            ipaddress.ip_address(value)
            result.append(value)
            continue
        except ValueError:
            pass
        if (value == "localhost" or "." in value) and re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value
        ):
            result.append(value)
    return result


def target_host(token: str) -> str | None:
    value = token.strip().strip("[](),")
    if not value or value.startswith("-") or "$" in value:
        return None
    if "://" in value:
        try:
            return (urlsplit(value).hostname or "").lower().rstrip(".") or None
        except ValueError:
            return None
    if "/" in value and not value.startswith("/"):
        try:
            parsed_host = urlsplit("//" + value).hostname
        except ValueError:
            parsed_host = None
        if parsed_host:
            return parsed_host.lower().rstrip(".")
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if ":" in value and value.count(":") == 1:
        value = value.split(":", 1)[0]
    value = value.strip("[]").rstrip(".").lower()
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if value == "localhost" or re.fullmatch(
        r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value
    ) and "." in value:
        return value
    return None


def host_allowed(host: str, patterns: list[str]) -> bool:
    if host in LOCAL_TARGETS:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host != pattern[2:]:
                return True
            continue
        if "/" in pattern and address is not None:
            try:
                if address in ipaddress.ip_network(pattern, strict=False):
                    return True
            except ValueError:
                continue
        elif host == pattern:
            return True
    return False


def network_target_tokens(executable: str, args: list[str]) -> list[str]:
    """Select target-bearing arguments without mistaking output files for hosts."""

    consumes_next: dict[str, set[str]] = {
        "curl": {
            "-o",
            "--output",
            "-H",
            "--header",
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "-X",
            "--request",
            "--max-time",
            "--connect-timeout",
            "--max-filesize",
            "-A",
            "--user-agent",
            "-u",
            "--user",
            "-b",
            "--cookie",
            "-c",
            "--cookie-jar",
            "--cacert",
            "--cert",
            "--key",
            "-w",
            "--write-out",
        },
        "wget": {
            "-O",
            "--output-document",
            "-o",
            "--output-file",
            "-a",
            "--append-output",
            "-T",
            "--timeout",
            "--header",
            "--user-agent",
            "--post-data",
            "--post-file",
            "--ca-certificate",
            "--certificate",
            "--private-key",
        },
        "ssh": {"-b", "-c", "-D", "-E", "-F", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"},
        "sftp": {"-B", "-b", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P", "-R", "-S"},
        "nmap": {"-iL", "-oA", "-oG", "-oN", "-oS", "-oX", "-p", "--exclude", "--excludefile", "--script", "--script-args"},
        "masscan": {"-p", "--ports", "-oB", "-oG", "-oJ", "-oL", "-oX", "--exclude", "--excludefile", "--rate"},
    }
    if executable == "scp":
        return [
            token
            for token in args
            if "://" in token or "@" in token or re.match(r"^[^/\s:]+:", token)
        ]

    targets: list[str] = []
    skip_next = False
    target_option = False
    option_values = consumes_next.get(executable, set())
    for token in args:
        if skip_next:
            if target_option:
                targets.append(token)
            skip_next = False
            target_option = False
            continue
        if token in {"--url"}:
            skip_next = True
            target_option = True
            continue
        if token.startswith("--url="):
            targets.append(token.split("=", 1)[1])
            continue
        if token in option_values:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        targets.append(token)
    if executable in {"ssh", "sftp", "dig", "host", "nslookup"}:
        return targets[:1]
    return targets


def network_violation(executable: str, args: list[str]) -> str | None:
    if executable not in NETWORK_COMMANDS:
        return None
    if args and all(arg in {"-h", "--help", "-V", "--version"} for arg in args):
        return None
    if executable in {"curl", "wget"} and any(
        arg in {"-L", "--location", "--max-redirect"}
        or arg.startswith(("--proxy", "--connect-to", "--resolve", "--unix-socket"))
        for arg in args
    ):
        return "Redirects and proxies are blocked because they can leave the CTF allowlist."
    hosts = [
        host
        for token in network_target_tokens(executable, args)
        if (host := target_host(token))
    ]
    if not hosts:
        return "Network command has no statically verifiable CTF target."
    patterns = allowed_patterns()
    denied = [host for host in hosts if not host_allowed(host, patterns)]
    if denied:
        return "Network target is not in CTF_AGENT_ALLOWED_TARGETS: " + ", ".join(denied[:3])
    return None


def modification_violation(
    executable: str,
    args: list[str],
    *,
    cwd: Path,
    root: Path,
) -> str | None:
    positional = [arg for arg in args if not arg.startswith("-")]
    if executable in {"rm", "rmdir", "unlink", "shred"}:
        recursive = executable == "rm" and any("r" in arg[1:] for arg in args if arg.startswith("-"))
        for token in positional:
            resolved = resolve_shell_path(token, cwd)
            if unsafe_write_path(token, cwd=cwd, root=root):
                return "Deletion outside the repository is blocked."
            if recursive and (token in {"*", ".", "./", "..", "../"} or resolved in {root, cwd}):
                return "Broad recursive deletion is blocked."
    elif executable in {"cp", "mv", "install"} and positional:
        if unsafe_write_path(positional[-1], cwd=cwd, root=root):
            return "Copy or move destination is outside the repository."
    elif executable in {"tee", "touch", "truncate", "mkdir"}:
        if any(unsafe_write_path(token, cwd=cwd, root=root) for token in positional):
            return "Write destination is outside the repository."
    elif executable in {"chmod", "chown", "chgrp"}:
        targets = positional[1:] if executable in {"chown", "chgrp"} else positional[1:]
        if any(unsafe_write_path(token, cwd=cwd, root=root) for token in targets):
            return "Permission or ownership change outside the repository is blocked."
    elif executable == "dd":
        for arg in args:
            if arg.startswith("of=") and unsafe_write_path(arg[3:], cwd=cwd, root=root):
                return "dd output outside the repository is blocked."
    elif executable == "find" and "-delete" in args:
        roots = [arg for arg in args if not arg.startswith("-")][:1]
        if not roots or any(unsafe_write_path(token, cwd=cwd, root=root) for token in roots):
            return "Out-of-scope find -delete is blocked."
    elif executable in {"sed", "perl"} and any(arg == "-i" or arg.startswith("-i") for arg in args):
        candidates = [arg for arg in positional if "/" in arg or Path(arg).exists()]
        if any(unsafe_write_path(token, cwd=cwd, root=root) for token in candidates):
            return "In-place edit outside the repository is blocked."
    return None


def git_violation(args: list[str]) -> str | None:
    if not args:
        return None
    subcommand = next((arg for arg in args if not arg.startswith("-")), "")
    if subcommand == "push":
        return "External Git writes are outside CTF solving scope."
    if subcommand == "reset" and "--hard" in args:
        return "Destructive git reset --hard is blocked."
    if subcommand == "clean" and any(arg.startswith("-f") or "f" in arg[1:] for arg in args if arg.startswith("-")):
        return "Destructive git clean is blocked."
    if subcommand in {"checkout", "restore"} and "--" in args:
        return "Destructive working-tree restoration is blocked."
    if subcommand == "config" and any(arg in {"--global", "--system"} for arg in args):
        return "Host-level Git configuration is outside CTF scope."
    if subcommand in {"clone", "fetch", "pull", "ls-remote"}:
        hosts = [host for token in args if (host := target_host(token))]
        if not hosts or any(not host_allowed(host, allowed_patterns()) for host in hosts):
            return "Git network target is not explicitly allowlisted."
    return None


def docker_violation(args: list[str]) -> str | None:
    joined = " ".join(args)
    dangerous = (
        "--privileged",
        "--pid=host",
        "--ipc=host",
        "--network=host",
        "/:/",
        "/dev:/dev",
        "docker.sock",
    )
    if any(value in joined for value in dangerous):
        return "Docker host-escape or host-wide mount option is blocked."
    if args[:2] in (["system", "prune"], ["volume", "prune"], ["network", "prune"]):
        return "Host-wide Docker prune is blocked."
    return None


def wrapped_command(executable: str, args: list[str]) -> list[str] | None:
    """Extract a wrapper's real command so policy cannot be bypassed with env/timeout."""

    index = 0
    if executable == "env":
        while index < len(args):
            token = args[index]
            if token in {"-S", "--split-string"} or token.startswith("--split-string="):
                return []
            if token in {"-u", "--unset", "-C", "--chdir"}:
                index += 2
                continue
            if token.startswith("-") or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*=.*", token, re.DOTALL
            ):
                index += 1
                continue
            break
    elif executable == "timeout":
        while index < len(args):
            token = args[index]
            if token in {"-k", "--kill-after", "-s", "--signal"}:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            index += 1  # duration
            break
    elif executable == "nice":
        if index < len(args) and args[index] in {"-n", "--adjustment"}:
            index += 2
        elif index < len(args) and re.fullmatch(r"-[0-9]+", args[index]):
            index += 1
    elif executable == "time":
        while index < len(args):
            token = args[index]
            if token in {"-f", "--format", "-o", "--output"}:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            break
    elif executable in {"command", "builtin", "nohup", "busybox"}:
        while index < len(args) and args[index].startswith("-"):
            index += 1
    elif executable in {"xargs", "parallel"}:
        value_options = {
            "-a",
            "--arg-file",
            "-E",
            "--eof",
            "-I",
            "--replace",
            "-L",
            "--max-lines",
            "-n",
            "--max-args",
            "-P",
            "--max-procs",
            "-s",
            "--max-chars",
        }
        while index < len(args):
            token = args[index]
            if token in value_options:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            break
    else:
        return None
    return args[index:]


def inspect_command(command: str, *, cwd: Path, root: Path, depth: int = 0) -> str | None:
    if depth > 2:
        return "Nested shell command depth exceeds the guard limit."
    if len(command) > MAX_COMMAND_CHARS:
        return "Command is too large for bounded policy inspection."
    stripped, saw_heredoc, heredoc_owner = strip_heredoc_bodies(command)
    if saw_heredoc and Path(heredoc_owner or "").name in {"bash", "sh", "zsh", "dash"}:
        return "Shell-interpreter heredocs bypass bounded inspection and are blocked."
    try:
        segments = split_segments(shell_tokens(stripped))
    except ValueError:
        return "Command could not be parsed safely."

    for segment in segments:
        if redirection_violation(segment, cwd=cwd, root=root):
            return "Shell redirection outside the repository is blocked."
        executable, args = executable_and_args(segment)
        if not executable:
            continue
        if sensitive_path_violation(executable, args):
            return "Access to credential or secret-bearing host paths is blocked."
        if executable.startswith("mkfs") or executable in ALWAYS_DENY:
            return f"Host-level or destructive command is blocked: {executable}."
        if executable in {"printenv"} or executable == "set" or (
            executable == "declare" and "-p" in args
        ):
            return "Bulk environment or secret enumeration is outside CTF scope."
        if executable == "env" and not any(not arg.startswith("-") and "=" not in arg for arg in args):
            return "Bulk environment enumeration is outside CTF scope."
        if executable in {
            "env",
            "timeout",
            "nice",
            "time",
            "command",
            "builtin",
            "nohup",
            "busybox",
            "xargs",
            "parallel",
        }:
            wrapped = wrapped_command(executable, args)
            if wrapped == [] and executable == "env" and any(
                arg in {"-S", "--split-string"} or arg.startswith("--split-string=")
                for arg in args
            ):
                return "env split-string bypasses bounded inspection and is blocked."
            if wrapped:
                nested = inspect_command(
                    " ".join(shlex.quote(token) for token in wrapped),
                    cwd=cwd,
                    root=root,
                    depth=depth + 1,
                )
                if nested:
                    return nested
        if executable in {"bash", "sh", "zsh", "dash"} and "-c" in args:
            index = args.index("-c")
            if index + 1 >= len(args):
                return "Shell -c command is missing inspectable input."
            nested = inspect_command(args[index + 1], cwd=cwd, root=root, depth=depth + 1)
            if nested:
                return nested
        if executable == "git":
            if reason := git_violation(args):
                return reason
        if executable in {"docker", "podman"}:
            if reason := docker_violation(args):
                return reason
        if reason := network_violation(executable, args):
            return reason
        if reason := modification_violation(executable, args, cwd=cwd, root=root):
            return reason
    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        deny("Malformed hook input; refusing to run an uninspected Bash command.")
        return 0

    if payload.get("hook_event_name") not in {None, "PreToolUse"}:
        return 0
    if payload.get("tool_name") not in {None, "Bash"}:
        return 0
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        deny("Missing Bash tool input; refusing an uninspected command.")
        return 0
    command = tool_input.get("command", tool_input.get("cmd"))
    if not isinstance(command, str) or not command.strip():
        deny("Missing Bash command string; refusing an uninspected command.")
        return 0

    try:
        cwd = Path(str(payload.get("cwd") or os.getcwd())).resolve()
    except (OSError, RuntimeError):
        cwd = Path.cwd().resolve()
    if reason := inspect_command(command, cwd=cwd, root=repo_root(cwd)):
        deny(reason)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
