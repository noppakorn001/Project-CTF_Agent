"""Safe inventory tooling for the public CryptoHack CTF Archive page.

The inventory parser is intentionally separate from challenge solving. It reads
only the official archive index, omits public solve counts/authors, and never
connects to ``archive.cryptohack.org`` challenge services. Downloading or
solving a listed challenge remains a separate, operator-approved action.
"""

from __future__ import annotations

import html
import hashlib
import json
import re
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from posixpath import normpath
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


ARCHIVE_URL = "https://cryptohack.org/challenges/ctf-archive/"
ALLOWED_HOST = "cryptohack.org"
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ArchiveFile:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class ArchiveChallenge:
    challenge_id: str
    year: int
    title: str
    description: str
    challenge_url: str
    files: tuple[ArchiveFile, ...] = ()
    remote_host: str | None = None
    remote_port: int | None = None

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["files"] = [asdict(item) for item in self.files]
        return value


def _text(fragment: str) -> str:
    fragment = re.sub(r"<br\s*/?>", "\n", fragment, flags=re.IGNORECASE)
    fragment = re.sub(r"<[^>]+>", " ", fragment)
    fragment = html.unescape(fragment)
    lines = [" ".join(line.split()) for line in fragment.splitlines()]
    return "\n".join(line for line in lines if line)


def _safe_official_url(value: str) -> str:
    absolute = urljoin(ARCHIVE_URL, value)
    parsed = urlparse(absolute)
    if parsed.scheme != "https" or parsed.netloc != ALLOWED_HOST:
        raise ValueError(f"refusing non-official archive URL: {value}")
    return absolute


def _parse_files(fragment: str) -> tuple[ArchiveFile, ...]:
    marker = re.search(r"Challenge files:</b>(.*)", fragment, flags=re.IGNORECASE | re.DOTALL)
    if not marker:
        return ()
    files: list[ArchiveFile] = []
    for href, name in re.findall(r'href="([^"]+)"[^>]*>([^<]+)</a>', marker.group(1), flags=re.IGNORECASE):
        if "/static/challenges/" not in href:
            continue
        files.append(ArchiveFile(_text(name), _safe_official_url(href)))
    return tuple(files)


def parse_archive_html(source: str, *, base_url: str = ARCHIVE_URL) -> list[ArchiveChallenge]:
    """Parse current archive cards without using solution metadata."""

    challenges: list[ArchiveChallenge] = []
    pattern = re.compile(
        r'<li[^>]+class="[^"]*challenge[^"]*"[^>]*data-stage="ctf-archive-(\d{4})"[^>]*>(.*?)</li>',
        flags=re.IGNORECASE | re.DOTALL,
    )
    for year_text, chunk in pattern.findall(source):
        id_match = re.search(r'data-challenge="([^"]+)"', chunk, flags=re.IGNORECASE)
        title_match = re.search(r'<div[^>]+class="challenge-text[^>]*>(.*?)</div>', chunk, flags=re.IGNORECASE | re.DOTALL)
        if not id_match or not title_match:
            continue
        challenge_id = html.unescape(id_match.group(1)).strip()
        title = _text(title_match.group(1))
        description_match = re.search(
            r'<div[^>]+class="challengeDescription"[^>]*>(.*?)</div>',
            chunk,
            flags=re.IGNORECASE | re.DOTALL,
        )
        description = _text(description_match.group(1)) if description_match else ""
        description = re.split(r"\bChallenge contributed by\b", description, maxsplit=1)[0].strip()
        remote_match = re.search(
            r'Connect at\s*<code>([A-Za-z0-9.:-]+)\s+(\d{1,5})</code>',
            chunk,
            flags=re.IGNORECASE,
        )
        remote_host = remote_match.group(1) if remote_match else None
        remote_port = int(remote_match.group(2)) if remote_match else None
        challenges.append(
            ArchiveChallenge(
                challenge_id=challenge_id,
                year=int(year_text),
                title=title,
                description=description,
                challenge_url=urljoin(base_url, f"/challenges/{challenge_id}/"),
                files=_parse_files(chunk),
                remote_host=remote_host,
                remote_port=remote_port,
            )
        )
    return challenges


def fetch_archive_html(url: str = ARCHIVE_URL, *, timeout: float = 15.0) -> str:
    """Fetch only the official index after an explicit operator request."""

    if _safe_official_url(url) != ARCHIVE_URL:
        raise ValueError("only the canonical CryptoHack archive index is allowed")
    request = Request(url, headers={"User-Agent": "CTF-Agent archive inventory"})
    with urlopen(request, timeout=timeout) as response:
        data = response.read(2_000_000)
    return data.decode("utf-8", "replace")


def _safe_static_url(value: str) -> str:
    absolute = _safe_official_url(value)
    if not urlparse(absolute).path.startswith("/static/challenges/"):
        raise ValueError(f"refusing non-challenge static URL: {value}")
    return absolute


def _safe_component(value: str) -> str:
    if not value or value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._-]+", value):
        raise ValueError(f"unsafe archive path component: {value!r}")
    return value


def download_static_files(
    records: list[dict[str, Any]],
    output_dir: Path,
    *,
    timeout: float = 30.0,
    max_file_bytes: int = MAX_FILE_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> dict[str, Any]:
    """Download only linked official static files into a preserved tree.

    This function never extracts or executes an artifact.  Existing regular
    files are retained, while symlinks and path traversal are rejected.  The
    caller must explicitly invoke it; inventory generation itself is index-only.
    """

    if not 1 <= max_file_bytes <= MAX_FILE_BYTES or not 1 <= max_total_bytes <= MAX_TOTAL_BYTES:
        raise ValueError("download caps are outside the safe bounds")
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    downloaded: list[dict[str, Any]] = []
    total_bytes = 0
    for record in records:
        year = _safe_component(str(record["year"]))
        challenge_id = _safe_component(str(record["challenge_id"]))
        for file_record in record.get("files", []):
            name = _safe_component(str(file_record["name"]))
            url = _safe_static_url(str(file_record["url"]))
            target = output_dir / year / challenge_id / name
            resolved_parent = target.parent.resolve()
            if output_dir not in resolved_parent.parents and resolved_parent != output_dir:
                raise ValueError(f"archive output escapes destination: {target}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_symlink():
                raise ValueError(f"refusing to overwrite symlink: {target}")
            if target.exists() and not target.is_file():
                raise ValueError(f"refusing non-regular output: {target}")
            digest = hashlib.sha256()
            size = 0
            if target.is_file():
                with target.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                        size += len(chunk)
                downloaded.append({"path": str(target), "url": url, "size": size, "sha256": digest.hexdigest(), "existing": True})
                total_bytes += size
                continue
            request = Request(url, headers={"User-Agent": "CTF-Agent archive artifact downloader"})
            with urlopen(request, timeout=timeout) as response:
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > max_file_bytes:
                    raise ValueError(f"static file exceeds cap: {url}")
                partial = target.with_name(target.name + ".part")
                if partial.exists() or partial.is_symlink():
                    raise ValueError(f"refusing pre-existing partial path: {partial}")
                try:
                    with partial.open("xb") as handle:
                        for chunk in iter(lambda: response.read(1024 * 1024), b""):
                            size += len(chunk)
                            if size > max_file_bytes or total_bytes + size > max_total_bytes:
                                raise ValueError("archive download size cap exceeded")
                            digest.update(chunk)
                            handle.write(chunk)
                    partial.replace(target)
                except BaseException:
                    partial.unlink(missing_ok=True)
                    raise
            total_bytes += size
            downloaded.append({"path": str(target), "url": url, "size": size, "sha256": digest.hexdigest(), "existing": False})
    return {"files": downloaded, "total_files": len(downloaded), "total_bytes": total_bytes}


def preflight_archives(
    root: Path,
    *,
    max_members: int = 4096,
    max_total_uncompressed: int = 512 * 1024 * 1024,
) -> list[dict[str, Any]]:
    """List ZIP central-directory metadata without extracting any member."""

    if not 1 <= max_members <= 100_000 or not 1 <= max_total_uncompressed <= 4 * 1024 * 1024 * 1024:
        raise ValueError("archive preflight caps are outside the safe bounds")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"archive root is not a directory: {root}")
    reports: list[dict[str, Any]] = []
    for archive in sorted(root.rglob("*.zip")):
        if archive.is_symlink() or not archive.is_file():
            raise ValueError(f"refusing non-regular archive: {archive}")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        members: list[dict[str, Any]] = []
        total_uncompressed = 0
        seen: set[str] = set()
        with zipfile.ZipFile(archive, "r") as handle:
            infos = handle.infolist()
            if len(infos) > max_members:
                raise ValueError(f"archive member cap exceeded: {archive}")
            for info in infos:
                name = info.filename.replace("\\", "/")
                normalized = normpath(name)
                parts = normalized.split("/")
                unsafe = (
                    not name
                    or name.startswith("/")
                    or ".." in parts
                    or normalized in {".", ""}
                    or normalized in seen
                    or "\x00" in name
                    or (info.external_attr & 0xF000) in {0x2000, 0x6000, 0xA000}
                )
                if unsafe:
                    raise ValueError(f"unsafe ZIP member {name!r} in {archive}")
                seen.add(normalized)
                total_uncompressed += info.file_size
                if total_uncompressed > max_total_uncompressed:
                    raise ValueError(f"archive expansion cap exceeded: {archive}")
                members.append(
                    {
                        "name": name,
                        "normalized": normalized,
                        "compressed_size": info.compress_size,
                        "uncompressed_size": info.file_size,
                        "is_dir": name.endswith("/"),
                    }
                )
        reports.append(
            {
                "path": str(archive),
                "sha256": digest,
                "member_count": len(members),
                "total_uncompressed": total_uncompressed,
                "members": members,
            }
        )
    return reports


def extract_zip_safely(
    archive_path: Path,
    output_dir: Path,
    *,
    members: set[str] | None = None,
    max_output_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    """Extract selected regular ZIP members after a complete safety preflight."""

    if not 1 <= max_output_bytes <= 512 * 1024 * 1024:
        raise ValueError("extraction output cap is outside the safe bounds")
    archive_path = archive_path.resolve()
    output_dir = output_dir.resolve()
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ValueError(f"archive is not a regular file: {archive_path}")
    output_dir.mkdir(parents=True, exist_ok=True)
    selected: list[zipfile.ZipInfo] = []
    total = 0
    with zipfile.ZipFile(archive_path, "r") as handle:
        infos = handle.infolist()
        if len(infos) > 4096:
            raise ValueError("archive member cap exceeded")
        seen: set[str] = set()
        for info in infos:
            name = info.filename.replace("\\", "/")
            normalized = normpath(name)
            parts = normalized.split("/")
            if (
                not name
                or name.startswith("/")
                or ".." in parts
                or normalized in {".", ""}
                or normalized in seen
                or "\x00" in name
                or (info.external_attr & 0xF000) in {0x2000, 0x6000, 0xA000}
            ):
                raise ValueError(f"unsafe ZIP member {name!r}")
            seen.add(normalized)
            if name.endswith("/"):
                continue
            if members is not None and name not in members and normalized not in members:
                continue
            total += info.file_size
            if total > max_output_bytes:
                raise ValueError("extraction output cap exceeded")
            selected.append(info)
        extracted: list[dict[str, Any]] = []
        for info in selected:
            name = info.filename.replace("\\", "/")
            target = output_dir.joinpath(*name.split("/"))
            parent = target.parent.resolve()
            if output_dir not in parent.parents and parent != output_dir:
                raise ValueError(f"extraction escapes destination: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() or target.is_symlink():
                raise ValueError(f"refusing to overwrite extraction target: {target}")
            partial = target.with_name(target.name + ".part")
            digest = hashlib.sha256()
            size = 0
            try:
                with handle.open(info, "r") as source, partial.open("xb") as destination:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        size += len(chunk)
                        if size > info.file_size or size > max_output_bytes:
                            raise ValueError(f"member size mismatch or cap exceeded: {name}")
                        digest.update(chunk)
                        destination.write(chunk)
                partial.replace(target)
            except BaseException:
                partial.unlink(missing_ok=True)
                raise
            extracted.append({"name": name, "path": str(target), "size": size, "sha256": digest.hexdigest()})
    return {"archive": str(archive_path), "files": extracted, "total_files": len(extracted), "total_bytes": total}


def inventory(source: str) -> list[dict[str, Any]]:
    return [item.as_dict() for item in parse_archive_html(source)]


def summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    years: dict[str, int] = {}
    offline = 0
    remote = 0
    files = 0
    for record in records:
        key = str(record["year"])
        years[key] = years.get(key, 0) + 1
        if record.get("remote_host"):
            remote += 1
        else:
            offline += 1
        files += len(record.get("files", []))
    return {"total": len(records), "years": dict(sorted(years.items())), "offline": offline, "remote": remote, "files": files}


def triage_inventory(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach deterministic route hints to inventory records, without solving."""

    from .playbooks import suggest_playbooks

    triaged: list[dict[str, Any]] = []
    for record in records:
        text = f"{record.get('title', '')} {record.get('description', '')}"
        matches = suggest_playbooks(text, limit=5)
        triaged.append(
            {
                "challenge_id": record["challenge_id"],
                "year": record["year"],
                "title": record["title"],
                "remote": bool(record.get("remote_host")),
                "files": [item["name"] for item in record.get("files", [])],
                "route_hints": [
                    {"id": playbook.id, "score": score} for playbook, score in matches
                ],
            }
        )
    return triaged


def write_inventory(path: Path, source: str, *, source_url: str = ARCHIVE_URL) -> dict[str, Any]:
    records = inventory(source)
    payload = {
        "schema_version": 1,
        "source_url": source_url,
        "policy": "index-only; no solution metadata; no remote challenge connections",
        "summary": summary(records),
        "challenges": records,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return payload
