"""Deterministic security, classification, routing, and budget primitives."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import math
import mimetypes
import re
import stat
import struct
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit


VERSION = "0.1.0"

PREPROCESSOR_VERSION = "2026.08.13.1"
MAX_PREPROCESS_BYTES = 256 * 1024
MAX_ZIP_MEMBERS = 64
MAX_ZIP_EXPANDED_BYTES = 512 * 1024
MAX_ZIP_MEMBER_SCAN_BYTES = 48 * 1024

ALLOWED_CATEGORIES = {
    "web",
    "pwn",
    "reverse",
    "crypto",
    "forensics",
    "misc",
    "osint",
    "hardware",
    "stego",
}

ALLOWED_STATUSES = {
    "queued",
    "ready",
    "running",
    "paused",
    "stopped",
    "solved",
    "rejected",
}

DEFAULT_SETTINGS: dict[str, Any] = {
    "global_token_budget": 500_000,
    "per_challenge_token_budget": 50_000,
    "reserve_percent": 20,
    "max_iterations": 12,
    "max_large_model_calls": 2,
    "max_tool_output_bytes": 64_000,
    "max_context_tokens": 12_000,
    "max_model_output_tokens": 1_200,
    "provider": "mock",
    "network_enabled": False,
    "tier_models": {
        "tool": "deterministic",
        "luna": "gpt-5.6-luna",
        "terra": "gpt-5.6-terra",
        "sol": "gpt-5.6-sol",
    },
}


def utc_now() -> str:
    """Return a sortable UTC timestamp."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stable_hash(value: Any) -> str:
    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class InjectionScan:
    score: float
    signals: tuple[str, ...]
    hostile: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "signals": list(self.signals),
            "hostile": self.hostile,
        }


_INJECTION_RULES: tuple[tuple[str, re.Pattern[str], float], ...] = (
    (
        "instruction_override",
        re.compile(
            r"\b(ignore|disregard|forget)\b.{0,45}\b(previous|prior|system|developer)"
            r".{0,25}\b(instruction|prompt|message)s?\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.40,
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(system prompt|api[\s_-]?key|access token|private key|environment variables?|"
            r"\benv\b|credentials?|secrets?)\b.{0,50}\b(print|show|reveal|send|dump|expose|read)\b"
            r"|\b(print|show|reveal|send|dump|expose|read)\b.{0,50}\b(system prompt|api[\s_-]?key|"
            r"access token|private key|environment variables?|\benv\b|credentials?|secrets?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.65,
    ),
    (
        "forced_expensive_model",
        re.compile(
            r"\b(use|invoke|switch to|call)\b.{0,35}\b(strongest|largest|most powerful|"
            r"ultra|expensive)\b.{0,15}\b(model|reasoning)?\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.30,
    ),
    (
        "repetition_request",
        re.compile(
            r"\b(repeat|print|output|analy[sz]e)\b.{0,55}"
            r"\b([1-9][0-9]{3,}|million|billion|forever|endless(?:ly)?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.35,
    ),
    (
        "recursive_instruction",
        re.compile(
            r"\b(recurs(?:e|ive|ively|ion)|call (?:the )?model again|spawn .{0,20}agents?"
            r"|never stop|keep (?:going|calling))\b",
            re.IGNORECASE,
        ),
        0.35,
    ),
    (
        "fake_authority",
        re.compile(
            r"\b(you are now|act as)\b.{0,30}\b(admin(?:istrator)?|root|system|developer)\b"
            r"|\b(admin(?:istrator)?|system|developer) (?:message|instruction)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.25,
    ),
    (
        "massive_output",
        re.compile(
            r"\b(unlimited|max(?:imum)?|huge|gigantic|entire)\b.{0,25}"
            r"\b(output|response|dump|log|file)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        0.30,
    ),
)

_LONG_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{256,}={0,2})")


def scan_prompt_injection(text: str, *, max_scan_chars: int = 200_000) -> InjectionScan:
    """Score hostile instructions without ever treating them as authority."""

    if not isinstance(text, str):
        text = str(text)
    sample = text[:max_scan_chars]
    score = 0.0
    signals: list[str] = []
    for name, pattern, weight in _INJECTION_RULES:
        if pattern.search(sample):
            score += weight
            signals.append(name)
    if len(text) > max_scan_chars:
        score += 0.15
        signals.append("oversized_text")
    if _LONG_BASE64.search(sample):
        score += 0.20
        signals.append("large_base64")
    rounded = round(min(score, 1.0), 2)
    return InjectionScan(rounded, tuple(signals), rounded >= 0.60)


def artifact_metadata(
    name: str,
    data: bytes,
    media_type: str | None = None,
) -> dict[str, Any]:
    """Return safe, deterministic metadata. Raw bytes are never returned."""

    lower_name = name.lower()
    guessed = media_type or mimetypes.guess_type(name)[0] or "application/octet-stream"
    magic = data[:16]
    kind = "binary"
    hints: list[str] = []

    if magic.startswith(b"\x7fELF"):
        kind = "elf"
        guessed = "application/x-elf"
        hints.extend(("reverse", "pwn"))
    elif magic.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "image"
        guessed = "image/png"
        hints.extend(("forensics", "stego"))
    elif magic.startswith(b"\xff\xd8\xff"):
        kind = "image"
        guessed = "image/jpeg"
        hints.extend(("forensics", "stego"))
    elif magic.startswith(b"PK\x03\x04"):
        kind = "archive"
        guessed = "application/zip"
        hints.append("forensics")
    elif magic.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a")):
        kind = "packet_capture"
        guessed = "application/vnd.tcpdump.pcap"
        hints.append("forensics")
    elif magic.startswith(b"%PDF"):
        kind = "document"
        guessed = "application/pdf"
        hints.append("forensics")
    elif magic.startswith(b"MZ"):
        kind = "executable"
        guessed = "application/vnd.microsoft.portable-executable"
        hints.append("reverse")
    elif _looks_textual(data):
        kind = "text"
        if guessed == "application/octet-stream":
            guessed = "text/plain"

    extension_hints: tuple[tuple[set[str], tuple[str, ...]], ...] = (
        ({".html", ".htm", ".js", ".php", ".css"}, ("web",)),
        ({".c", ".so", ".elf", ".out"}, ("pwn", "reverse")),
        ({".exe", ".dll", ".apk", ".dex", ".wasm"}, ("reverse",)),
        ({".pcap", ".pcapng", ".mem", ".raw", ".dmp", ".evtx"}, ("forensics",)),
        ({".png", ".jpg", ".jpeg", ".gif", ".bmp", ".wav"}, ("forensics", "stego")),
        ({".pem", ".pub", ".enc"}, ("crypto",)),
        ({".v", ".sv", ".vhd", ".vhdl", ".bit"}, ("hardware",)),
    )
    suffix = "." + lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""
    for extensions, categories in extension_hints:
        if suffix in extensions:
            hints.extend(categories)

    return {
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "media_type": guessed,
        "kind": kind,
        "category_hints": list(dict.fromkeys(hints)),
    }


def _looks_textual(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        printable = sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in sample)
        return printable / len(sample) > 0.90
    printable = sum(char in "\t\n\r" or char.isprintable() for char in decoded)
    return printable / max(1, len(decoded)) > 0.90


_FLAG_SHAPED_BYTES = re.compile(
    rb"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9_-]{0,31}\{[^\r\n{}]{1,160}\})"
)


def preprocess_artifact(
    name: str,
    data: bytes,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract compact, replayable CTF facts without returning raw artifact bytes.

    The parser deliberately supports a small set of deterministic, bounded routes.
    It never writes or executes supplied data.  Candidate strings are retained only
    with a stable source locator so verification can rescan the original bytes.
    """

    info = dict(metadata or artifact_metadata(name, data))
    artifact_hash = str(info.get("sha256") or hashlib.sha256(data).hexdigest())
    kind = str(info.get("kind") or "binary")
    result: dict[str, Any] = {
        "version": PREPROCESSOR_VERSION,
        "artifact_name": name,
        "artifact_sha256": artifact_hash,
        "kind": kind,
        "scanned_bytes": min(len(data), MAX_PREPROCESS_BYTES),
        "truncated": len(data) > MAX_PREPROCESS_BYTES,
        "facts": [],
        "candidates": [],
        "safety_notes": [],
    }

    if kind == "archive" and data.startswith(b"PK\x03\x04"):
        _preprocess_zip(data, result)
    elif kind == "image" and data.startswith(b"\x89PNG\r\n\x1a\n"):
        _preprocess_png(data, result)
    elif kind == "elf" and data.startswith(b"\x7fELF"):
        _preprocess_elf(data, result)
    elif kind == "text" or _looks_textual(data[: min(len(data), 8192)]):
        _preprocess_text(data, result, label="text")
    else:
        _preprocess_binary(data, result)

    result["candidates"] = _dedupe_candidates(result["candidates"])
    result["facts"] = result["facts"][:16]
    result["safety_notes"] = result["safety_notes"][:8]
    return result


def _preprocess_text(data: bytes, result: dict[str, Any], *, label: str) -> None:
    segments = _bounded_segments(data, MAX_PREPROCESS_BYTES)
    candidate_count = 0
    line_count = 0
    for offset, segment in segments:
        line_count += segment.count(b"\n")
        candidate_count += _append_candidates(
            segment,
            result,
            locator_prefix=f"{label}:byte",
            base_offset=offset,
            method="bounded_text_scan",
        )
    result["facts"].append(
        f"{label} inspection scanned {sum(len(segment) for _, segment in segments)} bytes, "
        f"{line_count + 1 if segments else 0} lines, and found {candidate_count} flag-shaped strings"
    )
    _detect_large_interpolation(data, result)


def _detect_large_interpolation(data: bytes, result: dict[str, Any]) -> None:
    """Recognize a dense consecutive-point stream without allocating a matrix.

    This is deliberately a routing hint, not an interpolator.  The first few
    lines are enough to identify the common Vandermonde trap; the complete
    artifact remains preserved and withheld from model context.
    """

    if len(data) <= MAX_PREPROCESS_BYTES:
        return
    sample = data[:16_384].decode("ascii", errors="ignore")
    points: list[tuple[int, int]] = []
    for line in sample.splitlines()[:32]:
        fields = line.split()
        if len(fields) != 2 or not all(re.fullmatch(r"\d+", item) for item in fields):
            break
        points.append((int(fields[0]), int(fields[1])))
    if len(points) < 8 or [x for x, _ in points] != list(range(len(points))):
        return
    name = str(result.get("artifact_name", "")).lower()
    if "encoded" not in name and "matrix" not in sample.lower():
        return
    result["facts"].append(
        "Large consecutive-point stream detected; route to fast finite-field "
        "interpolation and never materialize a dense Vandermonde matrix."
    )
    result["safety_notes"].append(
        "Dense interpolation is resource-intensive; raw artifact stays truncated "
        "and model escalation is paused until a bounded fast solver is available."
    )


def _preprocess_binary(data: bytes, result: dict[str, Any]) -> None:
    candidate_count = 0
    for offset, segment in _bounded_segments(data, MAX_PREPROCESS_BYTES):
        candidate_count += _append_candidates(
            segment,
            result,
            locator_prefix="binary:byte",
            base_offset=offset,
            method="bounded_binary_scan",
        )
    result["facts"].append(
        f"bounded binary inspection scanned {result['scanned_bytes']} bytes and found "
        f"{candidate_count} flag-shaped strings"
    )


def _preprocess_elf(data: bytes, result: dict[str, Any]) -> None:
    if len(data) < 20:
        result["safety_notes"].append("ELF header is truncated")
        return
    elf_class = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown-class")
    endian = {1: "little-endian", 2: "big-endian"}.get(data[5], "unknown-endian")
    byte_order = "<" if data[5] == 1 else ">" if data[5] == 2 else None
    machine = "unknown"
    if byte_order:
        machine_id = struct.unpack_from(byte_order + "H", data, 18)[0]
        machine = {
            3: "x86",
            40: "ARM",
            62: "x86-64",
            183: "AArch64",
            243: "RISC-V",
        }.get(machine_id, f"machine-{machine_id}")
    result["facts"].append(f"ELF header: {elf_class}, {endian}, {machine}")
    _preprocess_binary(data, result)


def _preprocess_png(data: bytes, result: dict[str, Any]) -> None:
    cursor = 8
    chunks: list[str] = []
    candidate_count = 0
    iend_end: int | None = None
    while cursor + 12 <= len(data):
        length = struct.unpack_from(">I", data, cursor)[0]
        chunk_end = cursor + 12 + length
        if chunk_end > len(data):
            result["safety_notes"].append("PNG chunk exceeds artifact bounds")
            break
        raw_type = data[cursor + 4 : cursor + 8]
        chunk_type = raw_type.decode("ascii", errors="replace")
        chunks.append(chunk_type)
        payload_start = cursor + 8
        if chunk_type in {"tEXt", "iTXt"}:
            payload = data[payload_start : min(payload_start + length, payload_start + MAX_ZIP_MEMBER_SCAN_BYTES)]
            candidate_count += _append_candidates(
                payload,
                result,
                locator_prefix=f"png:{chunk_type}:byte",
                base_offset=payload_start,
                method="png_text_chunk_scan",
            )
        cursor = chunk_end
        if chunk_type == "IEND":
            iend_end = cursor
            break
    if iend_end is None:
        result["safety_notes"].append("PNG IEND chunk was not found")
    else:
        trailing = data[iend_end:]
        if trailing:
            for offset, segment in _bounded_segments(trailing, MAX_PREPROCESS_BYTES):
                candidate_count += _append_candidates(
                    segment,
                    result,
                    locator_prefix="png:trailing:byte",
                    base_offset=iend_end + offset,
                    method="png_trailing_scan",
                )
    chunk_summary = ", ".join(chunks[:12]) or "none"
    result["facts"].append(
        f"PNG chunks: {chunk_summary}; trailing bytes: {len(data) - iend_end if iend_end is not None else 'unknown'}; "
        f"flag-shaped strings: {candidate_count}"
    )


def _preprocess_zip(data: bytes, result: dict[str, Any]) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                result["safety_notes"].append(
                    f"ZIP has {len(members)} members, above the {MAX_ZIP_MEMBERS} preprocessing cap"
                )
                return
            total = sum(member.file_size for member in members)
            if total > MAX_ZIP_EXPANDED_BYTES:
                result["safety_notes"].append(
                    f"ZIP declares {total} expanded bytes, above the {MAX_ZIP_EXPANDED_BYTES} preprocessing cap"
                )
                return
            unsafe = [_unsafe_zip_member_reason(member) for member in members]
            unsafe = [reason for reason in unsafe if reason]
            if unsafe:
                result["safety_notes"].append("ZIP rejected before extraction: " + unsafe[0])
                return
            text_members = 0
            candidate_count = 0
            for member in members:
                if member.is_dir() or member.file_size > MAX_ZIP_MEMBER_SCAN_BYTES:
                    continue
                with archive.open(member, "r") as source:
                    content = source.read(MAX_ZIP_MEMBER_SCAN_BYTES + 1)
                if len(content) > MAX_ZIP_MEMBER_SCAN_BYTES or not _looks_textual(content):
                    continue
                text_members += 1
                candidate_count += _append_candidates(
                    content,
                    result,
                    locator_prefix=f"zip:{member.filename}:byte",
                    base_offset=0,
                    method="zip_text_member_scan",
                )
            result["facts"].append(
                f"ZIP preflight accepted {len(members)} members / {total} declared bytes; "
                f"scanned {text_members} text members and found {candidate_count} flag-shaped strings"
            )
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        result["safety_notes"].append(f"ZIP parsing failed safely: {type(exc).__name__}")


def _unsafe_zip_member_reason(member: zipfile.ZipInfo) -> str | None:
    name = member.filename.replace("\\", "/")
    parts = [part for part in name.split("/") if part]
    if (
        not name
        or name.startswith("/")
        or re.match(r"^[A-Za-z]:", name)
        or any(part in {".", ".."} for part in parts)
    ):
        return f"unsafe path {member.filename!r}"
    mode = member.external_attr >> 16
    if stat.S_ISLNK(mode):
        return f"symlink member {member.filename!r}"
    if any((stat.S_ISCHR(mode), stat.S_ISBLK(mode), stat.S_ISFIFO(mode), stat.S_ISSOCK(mode))):
        return f"special-file member {member.filename!r}"
    if member.flag_bits & 0x1:
        return f"encrypted member {member.filename!r}"
    return None


def _bounded_segments(data: bytes, cap: int) -> list[tuple[int, bytes]]:
    if len(data) <= cap:
        return [(0, data)]
    half = max(1, cap // 2)
    return [(0, data[:half]), (len(data) - half, data[-half:])]


def _append_candidates(
    data: bytes,
    result: dict[str, Any],
    *,
    locator_prefix: str,
    base_offset: int,
    method: str,
) -> int:
    added = 0
    for match in _FLAG_SHAPED_BYTES.finditer(data):
        try:
            value = match.group(1).decode("ascii")
        except UnicodeDecodeError:
            continue
        locator = f"{locator_prefix}:{base_offset + match.start(1)}"
        evidence_id = stable_hash(
            {
                "artifact": result["artifact_sha256"],
                "candidate": value,
                "locator": locator,
                "method": method,
            }
        )[:20]
        result["candidates"].append(
            {
                "value": value,
                "evidence_id": evidence_id,
                "artifact_sha256": result["artifact_sha256"],
                "artifact_name": result["artifact_name"],
                "locator": locator,
                "method": method,
            }
        )
        added += 1
    return added


def _dedupe_candidates(candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        value = candidate.get("value")
        evidence_id = candidate.get("evidence_id")
        if isinstance(value, str) and isinstance(evidence_id, str):
            unique[(value, evidence_id)] = dict(candidate)
    return list(unique.values())


@dataclass(frozen=True)
class Classification:
    category: str
    confidence: float
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
        }


_CATEGORY_TERMS: dict[str, tuple[str, ...]] = {
    "web": (
        "http",
        "website",
        "web app",
        "cookie",
        "jwt",
        "sql injection",
        "xss",
        "ssrf",
        "ssti",
        "endpoint",
        "graphql",
    ),
    "pwn": (
        "buffer overflow",
        "heap",
        "rop",
        "shellcode",
        "format string",
        "libc",
        "nc ",
        "segmentation fault",
    ),
    "reverse": (
        "reverse engineer",
        "decompile",
        "disassemble",
        "binary",
        "malware",
        "apk",
        "license check",
    ),
    "crypto": (
        "cipher",
        "rsa",
        "aes",
        "nonce",
        "modulus",
        "plaintext",
        "ciphertext",
        "elliptic",
        "decrypt",
        "hash collision",
    ),
    "forensics": (
        "pcap",
        "packet",
        "memory dump",
        "disk image",
        "metadata",
        "timeline",
        "deleted file",
        "network capture",
    ),
    "osint": (
        "geolocate",
        "whois",
        "public records",
        "social media",
        "identify this place",
        "open source intelligence",
    ),
    "hardware": ("firmware", "uart", "jtag", "logic analyzer", "fpga", "verilog"),
    "stego": ("steganography", "hidden in the image", "lsb", "spectrogram"),
}


def classify_challenge(
    description: str,
    artifacts: Sequence[Mapping[str, Any]] = (),
    requested_category: str | None = None,
) -> Classification:
    """Classify using only local rules and artifact metadata."""

    scores = {category: 0.0 for category in ALLOWED_CATEGORIES}
    reasons: dict[str, list[str]] = {category: [] for category in ALLOWED_CATEGORIES}
    lower = (description or "").lower()

    for category, terms in _CATEGORY_TERMS.items():
        matches = [term for term in terms if term in lower]
        if matches:
            scores[category] += min(4.0, len(matches) * 1.25)
            reasons[category].append("description:" + ",".join(matches[:3]))

    for artifact in artifacts:
        for hint in artifact.get("category_hints", ()):
            if hint in scores:
                scores[hint] += 2.0
                reasons[hint].append(f"artifact:{artifact.get('kind', 'unknown')}")

    if requested_category in ALLOWED_CATEGORIES and requested_category != "misc":
        scores[requested_category] += 3.0
        reasons[requested_category].append("operator_hint")

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    category, top_score = ranked[0]
    if top_score <= 0:
        category = requested_category if requested_category in ALLOWED_CATEGORIES else "misc"
        return Classification(category, 0.35, ("no_strong_signal",))

    second = ranked[1][1]
    confidence = min(0.98, 0.55 + (top_score - second) * 0.09 + top_score * 0.035)
    return Classification(category, round(confidence, 2), tuple(reasons[category]))


def _target_host(target: str) -> str:
    value = target.strip()
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value.strip("[]"))).lower()
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else "//" + value)
    try:
        host = parsed.hostname
    except ValueError:
        return ""
    return (host or "").rstrip(".").lower()


def validate_scope_pattern(pattern: str) -> tuple[str, str]:
    """Normalize a host/IP/CIDR scope and reject dangerously broad patterns."""

    value = pattern.strip()
    if not value or len(value) > 253 or any(char.isspace() for char in value):
        raise ValueError("scope must be a non-empty host, IP, or CIDR")
    if value in {"*", "*.*", "0.0.0.0/0", "::/0"}:
        raise ValueError("global wildcard scopes are not allowed")
    if "/" in value and "://" not in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("invalid CIDR scope") from exc
        if network.num_addresses > 65_536:
            raise ValueError("CIDR scope is too broad")
        return str(network), "cidr"
    raw_ip = value.strip("[]")
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        address = None
    if address is not None:
        return str(address), "ip"
    wildcard = value.startswith("*.")
    host = _target_host(value[2:] if wildcard else value)
    if not host or host == "*":
        raise ValueError("scope must be a valid host, IP, or CIDR")
    try:
        ipaddress.ip_address(host)
        kind = "ip"
    except ValueError:
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("scope hostname contains invalid characters")
        kind = "wildcard_host" if wildcard else "host"
    return ("*." + host if wildcard else host), kind


class ScopeGuard:
    """Authorize only targets explicitly present in the operator allowlist."""

    def __init__(self, scopes: Iterable[Mapping[str, Any]] = ()) -> None:
        self.scopes = [scope for scope in scopes if scope.get("enabled", True)]

    def is_allowed(self, target: str) -> bool:
        host = _target_host(target)
        if not host:
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        for scope in self.scopes:
            pattern = str(scope.get("pattern", "")).lower()
            kind = scope.get("kind")
            if kind == "cidr" and address is not None:
                try:
                    if address in ipaddress.ip_network(pattern, strict=False):
                        return True
                except ValueError:
                    continue
            elif kind == "wildcard_host":
                suffix = pattern[1:]
                if host.endswith(suffix) and host != pattern[2:]:
                    return True
            elif kind in {"host", "ip"} and host == pattern:
                return True
        return False


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    reason: str
    cost: int
    global_budget: int
    global_spent: int
    global_reserve: int
    challenge_budget: int
    challenge_spent: int

    @property
    def global_spendable_remaining(self) -> int:
        return max(0, self.global_budget - self.global_reserve - self.global_spent)

    @property
    def challenge_remaining(self) -> int:
        return max(0, self.challenge_budget - self.challenge_spent)

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "cost": self.cost,
            "global_budget": self.global_budget,
            "global_spent": self.global_spent,
            "global_reserve": self.global_reserve,
            "global_spendable_remaining": self.global_spendable_remaining,
            "challenge_budget": self.challenge_budget,
            "challenge_spent": self.challenge_spent,
            "challenge_remaining": self.challenge_remaining,
        }


class BudgetManager:
    """Enforce per-challenge limits and a global reserve that is never automatic."""

    def __init__(
        self,
        global_budget: int,
        challenge_budget: int,
        reserve_percent: float = 20,
    ) -> None:
        self.global_budget = max(0, int(global_budget))
        self.challenge_budget = max(0, int(challenge_budget))
        self.reserve_percent = max(20.0, min(float(reserve_percent), 80.0))

    @property
    def reserve_tokens(self) -> int:
        return math.ceil(self.global_budget * self.reserve_percent / 100)

    def authorize(
        self,
        cost: int,
        *,
        global_spent: int,
        challenge_spent: int,
        allow_reserve: bool = False,
    ) -> BudgetDecision:
        requested = max(0, int(cost))
        global_limit = self.global_budget if allow_reserve else self.global_budget - self.reserve_tokens
        if challenge_spent + requested > self.challenge_budget:
            allowed, reason = False, "per_challenge_budget_exceeded"
        elif global_spent + requested > global_limit:
            allowed, reason = False, "global_reserve_protected"
        else:
            allowed, reason = True, "authorized"
        return BudgetDecision(
            allowed,
            reason,
            requested,
            self.global_budget,
            int(global_spent),
            self.reserve_tokens,
            self.challenge_budget,
            int(challenge_spent),
        )


@dataclass(frozen=True)
class RouteDecision:
    tier: str
    model: str
    reason: str
    estimated_tokens: int
    escalation: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "model": self.model,
            "reason": self.reason,
            "estimated_tokens": self.estimated_tokens,
            "escalation": self.escalation,
        }


class TierRouter:
    """Route work to deterministic tools first, then the cheapest adequate tier."""

    COSTS = {"tool": 0, "luna": 600, "terra": 1_800, "sol": 5_000}

    def __init__(self, tier_models: Mapping[str, str] | None = None) -> None:
        configured = dict(DEFAULT_SETTINGS["tier_models"])
        if tier_models:
            configured.update(
                {tier: str(model) for tier, model in tier_models.items() if tier in configured}
            )
        self.models = configured

    def route(
        self,
        *,
        task: str,
        complexity: float = 0.0,
        burn_score: float = 0.0,
        cheaper_failed: bool = False,
        large_calls: int = 0,
        max_large_calls: int = 2,
    ) -> RouteDecision:
        if task in {"metadata", "classify", "triage", "extract", "verify_format"}:
            tier, reason = "tool", "deterministic_first"
        elif burn_score >= 0.60:
            tier, reason = "tool", "hostile_input_blocks_model_escalation"
        elif complexity <= 0.30:
            tier, reason = "luna", "low_complexity"
        elif complexity <= 0.72 or not cheaper_failed:
            tier, reason = "terra", "moderate_analysis"
        elif large_calls >= max_large_calls:
            tier, reason = "terra", "large_model_call_cap"
        else:
            tier, reason = "sol", "justified_complex_escalation"
        return RouteDecision(
            tier,
            self.models[tier],
            reason,
            self.COSTS[tier],
            tier == "sol",
        )


class CircuitBreaker:
    """Track repeated failures and marginal progress in a serializable state."""

    @staticmethod
    def initial_state() -> dict[str, Any]:
        return {
            "iterations": 0,
            "no_progress_count": 0,
            "failure_counts": {},
            "large_model_calls": 0,
            "tripped": False,
            "trip_reason": None,
        }

    @classmethod
    def record(
        cls,
        state: Mapping[str, Any] | None,
        *,
        fingerprint: str,
        progress: bool,
        failed: bool = False,
        used_large_model: bool = False,
        max_iterations: int = 12,
    ) -> dict[str, Any]:
        result = dict(cls.initial_state())
        if state:
            result.update(state)
        result["failure_counts"] = dict(result.get("failure_counts") or {})
        result["iterations"] = int(result.get("iterations", 0)) + 1
        result["no_progress_count"] = 0 if progress else int(result.get("no_progress_count", 0)) + 1
        if failed:
            failures = result["failure_counts"]
            failures[fingerprint] = int(failures.get(fingerprint, 0)) + 1
        if used_large_model:
            result["large_model_calls"] = int(result.get("large_model_calls", 0)) + 1

        if failed and result["failure_counts"].get(fingerprint, 0) >= 2:
            result["tripped"] = True
            result["trip_reason"] = "same_hypothesis_failed_twice"
        elif result["no_progress_count"] >= 3:
            result["tripped"] = True
            result["trip_reason"] = "no_marginal_progress"
        elif result["iterations"] >= max(1, int(max_iterations)):
            result["tripped"] = True
            result["trip_reason"] = "iteration_limit"
        return result


def validate_settings_patch(current: Mapping[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the small public settings surface and return a complete value."""

    if not isinstance(patch, Mapping):
        raise ValueError("settings patch must be an object")
    allowed = set(DEFAULT_SETTINGS)
    unknown = set(patch) - allowed
    if unknown:
        raise ValueError("unknown settings: " + ", ".join(sorted(unknown)))
    result = dict(current)

    integer_ranges = {
        "global_token_budget": (1_000, 100_000_000),
        "per_challenge_token_budget": (100, 10_000_000),
        "max_iterations": (1, 100),
        "max_large_model_calls": (0, 20),
        "max_tool_output_bytes": (1_024, 10_000_000),
        "max_context_tokens": (512, 1_000_000),
        "max_model_output_tokens": (64, 32_000),
    }
    for key, (minimum, maximum) in integer_ranges.items():
        if key in patch:
            value = patch[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{key} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(f"{key} must be between {minimum} and {maximum}")
            result[key] = value

    if "reserve_percent" in patch:
        value = patch["reserve_percent"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("reserve_percent must be a number")
        if not 20 <= float(value) <= 80:
            raise ValueError("reserve_percent must be between 20 and 80")
        result["reserve_percent"] = value

    if "provider" in patch:
        if patch["provider"] not in {"mock", "openai"}:
            raise ValueError("provider must be mock or openai")
        result["provider"] = patch["provider"]

    if "network_enabled" in patch:
        if not isinstance(patch["network_enabled"], bool):
            raise ValueError("network_enabled must be a boolean")
        result["network_enabled"] = patch["network_enabled"]

    if "tier_models" in patch:
        models = patch["tier_models"]
        if not isinstance(models, Mapping):
            raise ValueError("tier_models must be an object")
        unknown_tiers = set(models) - {"tool", "luna", "terra", "sol"}
        if unknown_tiers:
            raise ValueError("unknown model tiers: " + ", ".join(sorted(unknown_tiers)))
        merged = dict(result.get("tier_models") or DEFAULT_SETTINGS["tier_models"])
        for tier, model in models.items():
            if not isinstance(model, str) or not model.strip() or len(model) > 100:
                raise ValueError(f"model for {tier} must be a non-empty string")
            merged[tier] = model.strip()
        result["tier_models"] = merged
    return result
