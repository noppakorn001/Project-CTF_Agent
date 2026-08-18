"""Bounded, offline web-challenge reconnaissance.

This module never performs network requests.  It turns captured HTML, headers,
and small text notes into compact route/parameter facts that a solver can use
before spending tokens or asking an operator to enable an allowlisted target.
All returned evidence is tied to a source hash and a byte/line locator so a
candidate can be replayed against the original artifact.
"""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, urlsplit

from .core import stable_hash


WEB_SOLVER_VERSION = "2026.08.12.1"
MAX_SOURCE_CHARS = 64_000
MAX_ROUTES = 96
MAX_PARAMS = 128
MAX_FORMS = 48
MAX_SIGNALS = 24

_FLAG_BYTES = re.compile(
    rb"(?<![A-Za-z0-9_-])([A-Za-z][A-Za-z0-9_-]{0,31}\{[^\r\n{}]{1,160}\})"
)
_URL_RE = re.compile(
    r"(?:(?:https?://)[^\s\"'<>]+|(?<!<)(?:/|\./|\.\./)[^\s\"'<>]+)"
)
_STATUS_RE = re.compile(r"(?im)^HTTP/\d(?:\.\d)?\s+(\d{3})\b")
_HEADER_RE = re.compile(r"(?im)^([A-Za-z][A-Za-z0-9-]{1,60}):\s*(.*?)\s*$")


class _MarkupParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.links: list[dict[str, Any]] = []
        self.forms: list[dict[str, Any]] = []
        self.inputs: list[dict[str, Any]] = []
        self.scripts = 0
        self.comments = 0
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        tag = tag.lower()
        if tag == "form":
            if len(self.forms) < MAX_FORMS:
                self._form = {
                    "action": values.get("action", ""),
                    "method": values.get("method", "GET").upper(),
                    "params": [],
                }
                self.forms.append(self._form)
        elif tag in {"input", "textarea", "select", "button"}:
            item = {
                "name": values.get("name", ""),
                "type": values.get("type", tag),
                "value": values.get("value", ""),
            }
            self.inputs.append(item)
            if self._form is not None:
                self._form["params"].append(item)
        elif tag in {"a", "link", "script", "img", "iframe", "object"}:
            attr = "href" if tag in {"a", "link"} else "src" if tag in {"script", "img", "iframe"} else "data"
            target = values.get(attr, "")
            if target and len(self.links) < MAX_ROUTES:
                self.links.append({"url": target, "tag": tag})
            if tag == "script":
                self.scripts += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None

    def handle_comment(self, _data: str) -> None:
        self.comments += 1


def solve_web_sources(
    sources: Iterable[Mapping[str, Any]],
    *,
    flag_format: str = "CTF{...}",
) -> dict[str, Any]:
    """Analyze captured web material without contacting any host."""

    normalized = _normalize_sources(sources)
    facts: list[str] = []
    signals: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    parameter_names: set[str] = set()
    status_codes: set[str] = set()
    source_kinds: set[str] = set()

    for source in normalized:
        text = source["text"]
        name = source["name"]
        lower = text.lower()
        source_kinds.add(_source_kind(name, text))
        parser = _parse_markup(text) if _looks_markup(name, text) else None
        if parser is not None:
            for link in parser.links:
                route = _route_record(link["url"], source, tag=link["tag"])
                if route is not None:
                    routes.append(route)
                    parameter_names.update(route["parameters"])
            for form in parser.forms:
                route = _route_record(form["action"] or "/", source, tag="form")
                if route is not None:
                    route["method"] = form["method"]
                    route["parameters"] = sorted(
                        {
                            *route["parameters"],
                            *{
                                item["name"]
                                for item in form["params"]
                                if item.get("name")
                            },
                        }
                    )[:16]
                    routes.append(route)
                    parameter_names.update(route["parameters"])
            if parser.forms:
                facts.append(f"[{name}] parsed {len(parser.forms)} form(s) and {len(parser.inputs)} input(s)")
            if parser.links:
                facts.append(f"[{name}] discovered {len(parser.links)} link/script/media reference(s)")
            if parser.scripts:
                signals.append(_signal("client_script", name, "script tags are present"))
            if parser.comments:
                signals.append(_signal("html_comments", name, "HTML comments may contain developer clues"))

        for path in _URL_RE.findall(text)[:MAX_ROUTES]:
            route = _route_record(path, source, tag="text")
            if route is not None:
                routes.append(route)
                parameter_names.update(route["parameters"])

        for match in _HEADER_RE.finditer(text):
            header, value = match.group(1).lower(), match.group(2)
            if header == "set-cookie" and "httponly" not in value.lower():
                signals.append(_signal("cookie_missing_httponly", name, "Set-Cookie lacks HttpOnly"))
            if header == "set-cookie" and "secure" not in value.lower():
                signals.append(_signal("cookie_missing_secure", name, "Set-Cookie lacks Secure"))
            if header in {"location", "set-cookie", "authorization", "www-authenticate"}:
                signals.append(_signal("header_" + header.replace("-", "_"), name, "security-relevant response header"))
        status_codes.update(_STATUS_RE.findall(text))

        if any(term in lower for term in ("jwt", "bearer ", "authorization:", "jsonwebtoken")):
            signals.append(_signal("jwt_or_bearer", name, "JWT/Bearer authentication vocabulary"))
        if any(term in lower for term in ("admin", "role", "user_id", "userid", "is_admin")):
            signals.append(_signal("authorization_surface", name, "role or user identity fields"))
        if any(term in lower for term in ("sql", "sqlite", "mysql", "syntax error", "internal server error")):
            signals.append(_signal("database_error_surface", name, "database/error vocabulary"))
        if any(term in lower for term in ("markdown", "onerror", "onmouseover", "<script", "javascript:")):
            signals.append(_signal("markup_injection_surface", name, "HTML/Markdown/script sink vocabulary"))

        for match in _FLAG_BYTES.finditer(text.encode("utf-8", errors="replace")):
            value = match.group(1).decode("ascii", errors="ignore")
            if _matches_flag(value, flag_format):
                candidates.append(_candidate(value, source, match.start(1), "web_source_flag_scan"))

    if parameter_names:
        interesting = sorted(parameter_names & {
            "id", "page", "user", "user_id", "userid", "role", "file", "path", "url", "next", "redirect", "token", "jwt", "query", "search"
        })
        facts.append("Parameter inventory: " + ", ".join(sorted(parameter_names)[:32]))
        if interesting:
            signals.append(_signal("high_value_parameters", ",".join(interesting), "common authorization/file/redirect parameters"))
    if status_codes:
        facts.append("Captured HTTP status codes: " + ", ".join(sorted(status_codes)))

    unique_routes = _dedupe_routes(routes)
    unique_signals = _dedupe_signals(signals)
    unique_candidates = _dedupe_candidates(candidates)
    if unique_routes:
        facts.append(f"Bounded route map contains {len(unique_routes)} unique path(s)")
    if unique_signals:
        facts.append(f"Deterministic web checks raised {len(unique_signals)} signal(s); no request was sent")
    return {
        "version": WEB_SOLVER_VERSION,
        "source_count": len(normalized),
        "source_kinds": sorted(source_kinds),
        "facts": list(dict.fromkeys(facts))[:24],
        "signals": unique_signals[:MAX_SIGNALS],
        "routes": unique_routes[:MAX_ROUTES],
        "parameters": sorted(parameter_names)[:MAX_PARAMS],
        "candidates": unique_candidates,
    }


def _normalize_sources(sources: Iterable[Mapping[str, Any]]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for source in sources:
        text = source.get("text")
        if not isinstance(text, str) or not text:
            continue
        result.append({
            "name": str(source.get("name") or "web-source")[:160],
            "sha256": str(source.get("sha256") or stable_hash(text)),
            "text": text[:MAX_SOURCE_CHARS],
        })
    return result


def _parse_markup(text: str) -> _MarkupParser:
    parser = _MarkupParser()
    try:
        parser.feed(text[:MAX_SOURCE_CHARS])
        parser.close()
    except Exception:
        # Malformed hostile markup is data, not a reason to fail the import.
        return _MarkupParser()
    return parser


def _looks_markup(name: str, text: str) -> bool:
    lower = name.lower()
    return lower.endswith((".html", ".htm", ".php", ".xml")) or bool(re.search(r"<\s*(html|form|a|script|input)\b", text, re.I))


def _source_kind(name: str, text: str) -> str:
    if _looks_markup(name, text):
        return "html"
    if _STATUS_RE.search(text) or _HEADER_RE.search(text):
        return "http"
    return "text"


def _route_record(url: str, source: Mapping[str, str], *, tag: str) -> dict[str, Any] | None:
    raw = html.unescape(url.strip())
    if not raw or raw.startswith(("javascript:", "data:", "mailto:", "#")):
        return None
    parsed = urlsplit(raw if "://" in raw else "//local" + (raw if raw.startswith("/") else "/" + raw))
    path = parsed.path or "/"
    if len(path) > 240:
        path = path[:240]
    params = {key[:80] for key, _ in parse_qsl(parsed.query, keep_blank_values=True) if key}
    return {
        "path": path,
        "method": "GET",
        "parameters": sorted(params)[:16],
        "tag": tag,
        "source": source["name"],
        "source_sha256": source["sha256"],
    }


def _signal(kind: str, source: str, reason: str) -> dict[str, str]:
    return {"kind": kind[:80], "source": source[:160], "reason": reason[:240]}


def _candidate(value: str, source: Mapping[str, str], offset: int, method: str) -> dict[str, Any]:
    locator = f"web:{source['name']}:byte:{max(0, offset)}"
    return {
        "value": value,
        "evidence_id": stable_hash({"source": source["sha256"], "value": value, "locator": locator, "method": method})[:20],
        "artifact_sha256": source["sha256"],
        "artifact_name": source["name"],
        "locator": locator,
        "method": method,
    }


def _matches_flag(value: str, flag_format: str) -> bool:
    if "..." in flag_format:
        prefix, suffix = flag_format.split("...", 1)
        return value.startswith(prefix) and value.endswith(suffix) and len(value) > len(prefix) + len(suffix)
    if "{...}" in flag_format:
        prefix = flag_format.split("{...}", 1)[0]
        return value.startswith(prefix + "{") and value.endswith("}")
    return value == flag_format


def _dedupe_routes(routes: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
    for route in routes:
        key = (str(route.get("method", "GET")), str(route.get("path", "/")), tuple(route.get("parameters", [])))
        result[key] = dict(route)
    return list(result.values())


def _dedupe_signals(signals: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for signal in signals:
        result[(str(signal.get("kind")), str(signal.get("source")))] = dict(signal)
    return list(result.values())


def _dedupe_candidates(candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in candidates:
        value, evidence = candidate.get("value"), candidate.get("evidence_id")
        if isinstance(value, str) and isinstance(evidence, str):
            result[(value, evidence)] = dict(candidate)
    return list(result.values())
