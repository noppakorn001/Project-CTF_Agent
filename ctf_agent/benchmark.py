"""Blind, offline benchmark bookkeeping for authorized CTF crypto challenges.

This module deliberately does not solve challenges or launch remote clients. It
validates an operator-supplied manifest, emits a blind challenge payload, and
aggregates recorded solver results into the metrics required by the benchmark
specification.  The primary dataset must be supplied separately and must not
contain picoCTF challenges or write-up-derived material.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


TIERS = ("intermediate", "advanced", "expert")
EXPECTED_TIER_COUNTS = {tier: 10 for tier in TIERS}
RESULT_STATES = (
    "SOLVED_CONFIRMED",
    "SOLVED_UNCONFIRMED",
    "PARTIAL",
    "FAILED",
    "TIMEOUT",
    "CONTAMINATED",
)
FAILURE_CLASSES = (
    "KNOWLEDGE_GAP",
    "REASONING_FAILURE",
    "TOOLING_GAP",
    "IMPLEMENTATION_BUG",
    "TIME_LIMIT",
    "COMPUTE_LIMIT",
    "UNCLASSIFIED",
)
FORBIDDEN_PRIMARY_MARKERS = ("picoctf", "writeup", "solution", "flag database")
ID_RE = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")


@dataclass(frozen=True, slots=True)
class ChallengeSpec:
    challenge_id: str
    tier: str
    description: str
    artifacts_dir: str
    flag_format: str | None = None
    remote: dict[str, Any] | None = None
    source_ref: str | None = None


@dataclass(frozen=True, slots=True)
class BenchmarkManifest:
    benchmark_id: str
    primary: bool
    expected_tiers: dict[str, int]
    challenges: tuple[ChallengeSpec, ...]


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def load_manifest(path: Path) -> BenchmarkManifest:
    """Load a manifest without exposing hidden metadata to a solver."""

    raw = _load_json(path)
    expected = raw.get("expected_tiers", EXPECTED_TIER_COUNTS)
    if not isinstance(expected, dict):
        raise ValueError("expected_tiers must be an object")
    challenges: list[ChallengeSpec] = []
    for item in raw.get("challenges", []):
        if not isinstance(item, dict):
            raise ValueError("every challenge entry must be an object")
        challenges.append(
            ChallengeSpec(
                challenge_id=str(item.get("id", "")),
                tier=str(item.get("tier", "")),
                description=str(item.get("description", "")),
                artifacts_dir=str(item.get("artifacts_dir", "")),
                flag_format=item.get("flag_format"),
                remote=item.get("remote"),
                source_ref=item.get("source_ref"),
            )
        )
    return BenchmarkManifest(
        benchmark_id=str(raw.get("benchmark_id", "")),
        primary=bool(raw.get("primary", True)),
        expected_tiers={str(key): int(value) for key, value in expected.items()},
        challenges=tuple(challenges),
    )


def _safe_path(root: Path, relative: str) -> Path | None:
    value = Path(relative)
    if not relative or value.is_absolute() or ".." in value.parts:
        return None
    resolved_root = root.resolve()
    resolved = (root / value).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        return None
    return resolved


def validate_manifest(
    manifest: BenchmarkManifest,
    root: Path,
    *,
    require_complete: bool = False,
) -> list[str]:
    """Return actionable validation errors; never contacts a remote target."""

    errors: list[str] = []
    if not manifest.benchmark_id:
        errors.append("benchmark_id is required")
    if set(manifest.expected_tiers) != set(TIERS):
        errors.append(f"expected_tiers must contain exactly {', '.join(TIERS)}")
    seen: set[str] = set()
    counts: Counter[str] = Counter()
    for spec in manifest.challenges:
        if not ID_RE.fullmatch(spec.challenge_id):
            errors.append(f"invalid challenge id: {spec.challenge_id!r}")
        if spec.challenge_id in seen:
            errors.append(f"duplicate challenge id: {spec.challenge_id}")
        seen.add(spec.challenge_id)
        if spec.tier not in TIERS:
            errors.append(f"{spec.challenge_id}: invalid tier {spec.tier!r}")
        counts[spec.tier] += 1
        description = _safe_path(root, spec.description)
        artifact_dir = _safe_path(root, spec.artifacts_dir)
        if description is None or not description.is_file():
            errors.append(f"{spec.challenge_id}: description file is missing or unsafe")
        if artifact_dir is None or not artifact_dir.is_dir():
            errors.append(f"{spec.challenge_id}: artifacts_dir is missing or unsafe")
        if spec.remote is not None:
            if not isinstance(spec.remote, dict) or spec.remote.get("authorized") is not True:
                errors.append(f"{spec.challenge_id}: remote requires authorized=true")
        if manifest.primary:
            searchable = " ".join(
                (spec.source_ref or "", spec.description, spec.artifacts_dir)
            ).lower()
            for marker in FORBIDDEN_PRIMARY_MARKERS:
                if marker in searchable:
                    errors.append(f"{spec.challenge_id}: primary dataset contains forbidden marker {marker!r}")
    if require_complete:
        if len(manifest.challenges) != 30:
            errors.append(f"primary benchmark requires 30 challenges, found {len(manifest.challenges)}")
        for tier, expected in EXPECTED_TIER_COUNTS.items():
            if counts[tier] != expected:
                errors.append(f"tier {tier} requires {expected}, found {counts[tier]}")
    return errors


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def blind_payload(manifest: BenchmarkManifest, challenge_id: str, root: Path) -> dict[str, Any]:
    """Return only the fields a blind solver is allowed to receive."""

    spec = next((item for item in manifest.challenges if item.challenge_id == challenge_id), None)
    if spec is None:
        raise KeyError(f"unknown challenge id: {challenge_id}")
    description_path = _safe_path(root, spec.description)
    artifacts_path = _safe_path(root, spec.artifacts_dir)
    if description_path is None or artifacts_path is None:
        raise ValueError("challenge paths are unsafe")
    artifacts: list[dict[str, Any]] = []
    for index, path in enumerate(sorted(item for item in artifacts_path.iterdir() if item.is_file())):
        artifacts.append(
            {
                "id": f"artifact_{index:03d}",
                "size": path.stat().st_size,
                "sha256": _sha256(path),
            }
        )
    payload: dict[str, Any] = {
        "challenge_id": spec.challenge_id,
        "description": description_path.read_text(encoding="utf-8"),
        "artifacts": artifacts,
    }
    if spec.flag_format:
        payload["flag_format"] = spec.flag_format
    if spec.remote:
        payload["remote"] = {key: spec.remote[key] for key in ("host", "port") if key in spec.remote}
    return payload


def load_results(path: Path) -> list[dict[str, Any]]:
    """Load newline-delimited result records, ignoring blank lines only."""

    results: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid result JSON on line {line_number}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"result on line {line_number} must be an object")
        results.append(value)
    return results


def validate_results(results: Iterable[dict[str, Any]], manifest: BenchmarkManifest) -> list[str]:
    known = {item.challenge_id: item.tier for item in manifest.challenges}
    errors: list[str] = []
    seen: set[str] = set()
    for index, result in enumerate(results, 1):
        challenge_id = str(result.get("challenge_id", ""))
        if challenge_id not in known:
            errors.append(f"result {index}: unknown challenge_id {challenge_id!r}")
        if challenge_id in seen:
            errors.append(f"result {index}: duplicate challenge_id {challenge_id}")
        seen.add(challenge_id)
        if result.get("tier") not in (None, known.get(challenge_id)):
            errors.append(f"result {index}: tier does not match manifest")
        if result.get("status") not in RESULT_STATES:
            errors.append(f"result {index}: invalid status")
        if result.get("failure_class") not in (None, *FAILURE_CLASSES):
            errors.append(f"result {index}: invalid failure_class")
        for key in ("solve_time_seconds", "token_cost", "tool_calls", "failed_hypotheses", "solver_attempts"):
            if key in result and (not isinstance(result[key], (int, float)) or result[key] < 0):
                errors.append(f"result {index}: {key} must be non-negative")
        for key in ("confidence_before", "confidence_after"):
            if key in result and (not isinstance(result[key], (int, float)) or not 0 <= result[key] <= 1):
                errors.append(f"result {index}: {key} must be between 0 and 1")
    return errors


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _tier_stats(results: list[dict[str, Any]], tier: str) -> dict[str, Any]:
    values = [result for result in results if result.get("tier") == tier]
    solved = sum(result.get("status") == "SOLVED_CONFIRMED" for result in values)
    return {"total": len(values), "solved": solved, "solve_rate": _rate(solved, len(values))}


def aggregate_metrics(
    results: Iterable[dict[str, Any]],
    manifest: BenchmarkManifest | None = None,
) -> dict[str, Any]:
    """Compute primary metrics while excluding contaminated records."""

    all_results = list(results)
    contaminated = [
        item
        for item in all_results
        if item.get("status") == "CONTAMINATED" or item.get("contaminated") is True
    ]
    valid = [
        item
        for item in all_results
        if item.get("status") != "CONTAMINATED" and item.get("contaminated") is not True
    ]
    solved = [item for item in valid if item.get("status") == "SOLVED_CONFIRMED"]
    times = [float(item["solve_time_seconds"]) for item in valid if item.get("solve_time_seconds") is not None]
    token_values = [float(item.get("token_cost", 0)) for item in valid]
    tool_values = [float(item.get("tool_calls", 0)) for item in valid]
    failed_values = [float(item.get("failed_hypotheses", 0)) for item in valid]
    attempts = [float(item.get("solver_attempts", 0)) for item in valid]
    timeout_count = sum(item.get("status") == "TIMEOUT" or item.get("timed_out") is True for item in valid)
    human_count = sum(item.get("human_intervention") is True for item in valid)
    before = [float(item["confidence_before"]) for item in valid if item.get("confidence_before") is not None]
    after = [float(item["confidence_after"]) for item in valid if item.get("confidence_after") is not None]
    techniques = Counter(str(item["technique"]) for item in valid if item.get("technique"))
    result: dict[str, Any] = {
        "total_records": len(all_results),
        "valid_records": len(valid),
        "contaminated_records": len(contaminated),
        "contamination_rate": _rate(len(contaminated), len(all_results)),
        "solved": len(solved),
        "solve_rate": _rate(len(solved), len(valid)),
        "median_solve_time_seconds": _percentile(times, 0.5),
        "p90_solve_time_seconds": _percentile(times, 0.9),
        "average_tokens_per_solved": _rate(sum(item.get("token_cost", 0) for item in solved), len(solved)),
        "average_tool_calls": _rate(sum(tool_values), len(valid)),
        "average_failed_hypotheses": _rate(sum(failed_values), len(valid)),
        "average_solver_attempts": _rate(sum(attempts), len(valid)),
        "timeout_rate": _rate(timeout_count, len(valid)),
        "human_intervention_rate": _rate(human_count, len(valid)),
        "average_confidence_before": _rate(sum(before), len(before)),
        "average_confidence_after": _rate(sum(after), len(after)),
        "technique_distribution": dict(sorted(techniques.items())),
        "difficulty_breakdown": {},
    }
    if manifest:
        result["difficulty_breakdown"] = {
            tier: _tier_stats(valid, tier) for tier in TIERS
        }
    result["readiness_level"] = readiness_level(result)
    return result


def readiness_level(metrics: dict[str, Any]) -> str:
    """Apply the prompt's conservative numeric readiness thresholds."""

    breakdown = metrics.get("difficulty_breakdown", {})
    intermediate = float((breakdown.get("intermediate") or {}).get("solve_rate") or 0)
    advanced = float((breakdown.get("advanced") or {}).get("solve_rate") or 0)
    expert = float((breakdown.get("expert") or {}).get("solve_rate") or 0)
    if advanced >= 0.75 and expert >= 0.40:
        return "LEVEL 4 — High-End CTF Solver"
    if intermediate >= 0.90 and advanced >= 0.60 and expert >= 0.20:
        return "LEVEL 3 — Advanced Competition Solver"
    if intermediate >= 0.70 and advanced >= 0.40:
        return "LEVEL 2 — Competition Ready"
    if intermediate > 0 or advanced > 0 or expert > 0:
        return "LEVEL 1 — picoCTF-Class Solver"
    return "LEVEL 0 — Educational Solver / insufficient benchmark evidence"


def render_report(
    manifest: BenchmarkManifest,
    results: Iterable[dict[str, Any]],
) -> str:
    metrics = aggregate_metrics(results, manifest)
    lines = [
        "# Executive Summary",
        "",
        "This report is generated from an operator-supplied blind crypto benchmark.",
        "Records marked `CONTAMINATED` are excluded from primary solve statistics.",
        "",
        "# System Configuration",
        "",
        "- Network: disabled by default; exact authorized instances only.",
        "- Solver policy: deterministic-first, explicit hypotheses, bounded escalation.",
        "- Submission: manual operator action only.",
        "",
        "# Challenge Dataset",
        "",
        f"- Benchmark ID: `{manifest.benchmark_id}`",
        f"- Manifest entries: {len(manifest.challenges)}",
        f"- Expected primary distribution: {manifest.expected_tiers}",
        "",
        "# Solve Statistics",
        "",
        f"- Records: {metrics['total_records']} (valid {metrics['valid_records']})",
        f"- Confirmed solved: {metrics['solved']}",
        f"- Solve rate: {metrics['solve_rate']}",
        f"- Median solve time (s): {metrics['median_solve_time_seconds']}",
        f"- P90 solve time (s): {metrics['p90_solve_time_seconds']}",
        f"- Average tokens per solved: {metrics['average_tokens_per_solved']}",
        f"- Average tool calls: {metrics['average_tool_calls']}",
        f"- Average failed hypotheses: {metrics['average_failed_hypotheses']}",
        f"- Timeout rate: {metrics['timeout_rate']}",
        f"- Human intervention rate: {metrics['human_intervention_rate']}",
        f"- Contamination rate: {metrics['contamination_rate']}",
        "",
        "# Difficulty Breakdown",
        "",
    ]
    for tier in TIERS:
        lines.append(f"- {tier}: {metrics['difficulty_breakdown'].get(tier, {})}")
    lines.extend(
        [
            "",
            "# Cryptographic Technique Breakdown",
            "",
            f"{json.dumps(metrics['technique_distribution'], ensure_ascii=False, sort_keys=True)}",
            "",
            "# Successful Challenges",
            "",
            "See result records; only `SOLVED_CONFIRMED` is counted.",
            "",
            "# Failed Challenges",
            "",
            "See result records and failure_class fields.",
            "",
            "# Failure Analysis",
            "",
            "Failure records must include hypotheses, tests, and a failure class.",
            "",
            "# Tooling Bottlenecks",
            "",
            "Populate from result notes; do not infer missing evidence.",
            "",
            "# Reasoning Bottlenecks",
            "",
            "Populate from failed hypotheses and progress logs.",
            "",
            "# Knowledge Gaps",
            "",
            "Distill only generalized techniques into `knowledge/crypto/`.",
            "",
            "# Comparison Against picoCTF Baseline",
            "",
            "picoCTF is historical context only and is not included in the primary dataset.",
            "",
            "# Competition Readiness Level",
            "",
            f"**{metrics['readiness_level']}**",
            "",
            "# Recommended Improvements",
            "",
            "- Fill the 30-entry non-picoCTF manifest with hashes and authorization notes.",
            "- Run blind payloads without exposing tier, author, year, or public rating.",
            "- Record clean replay evidence before marking a candidate confirmed.",
            "",
            "# Recommended Next Benchmark",
            "",
            "Add a new held-out 10/10/10 dataset from reputable public competitions.",
            "",
        ]
    )
    return "\n".join(lines)
