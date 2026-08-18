"""Dependency-free JSON API and static file server."""

from __future__ import annotations

import json
import mimetypes
import os
import posixpath
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from .service import CTFService, ServiceError
from .storage import Database


MAX_REQUEST_BYTES = 16 * 1024 * 1024
_CHALLENGE_ACTION = re.compile(
    r"^/api/challenges/([^/]+)/actions/(triage|solve|pause|resume|stop|verify)$"
)
_CHALLENGE_DETAIL = re.compile(r"^/api/challenges/([^/]+)$")
_SCOPE_DETAIL = re.compile(r"^/api/scopes/([0-9]+)$")


class CTFHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        service: CTFService,
        static_dir: Path,
    ) -> None:
        self.service = service
        self.static_dir = static_dir.resolve()
        super().__init__(address, CTFRequestHandler)

    def server_close(self) -> None:
        try:
            super().server_close()
        finally:
            self.service.db.close()


class CTFRequestHandler(BaseHTTPRequestHandler):
    server: CTFHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "CTFAgent/0.1"

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format_string: str, *args: Any) -> None:
        if os.environ.get("CTF_AGENT_HTTP_LOG") == "1":
            super().log_message(format_string, *args)

    def _dispatch(self, method: str) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query, keep_blank_values=False)
        try:
            if path.startswith("/api/"):
                response, status = self._api(method, path, query)
                self._send_json(response, status=status)
            elif method == "GET":
                self._serve_static(parsed.path)
            else:
                raise ServiceError("method not allowed", status=405, code="method_not_allowed")
        except ServiceError as exc:
            self._send_json(exc.as_dict(), status=exc.status)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            # Keep exception details and local paths out of HTTP responses.
            self._send_json(
                {
                    "ok": False,
                    "error": {
                        "code": "internal_error",
                        "message": "internal server error",
                    },
                },
                status=500,
            )

    def _api(
        self,
        method: str,
        path: str,
        query: dict[str, list[str]],
    ) -> tuple[Any, int]:
        service = self.server.service
        if method == "GET" and path == "/api/health":
            return service.health(), 200
        if method == "GET" and path == "/api/bootstrap":
            return service.bootstrap(), 200
        if path == "/api/challenges":
            if method == "GET":
                return {
                    "challenges": service.list_challenges(
                        status=_query_one(query, "status"),
                        category=_query_one(query, "category"),
                        search=_query_one(query, "search"),
                    )
                }, 200
            if method == "POST":
                challenge = service.create_challenge(self._read_json())
                return {"ok": True, "challenge": challenge}, 201
            raise ServiceError("method not allowed", status=405, code="method_not_allowed")

        action_match = _CHALLENGE_ACTION.fullmatch(path)
        if action_match:
            if method != "POST":
                raise ServiceError("method not allowed", status=405, code="method_not_allowed")
            challenge_id = unquote(action_match.group(1))
            action = action_match.group(2)
            return service.run_action(challenge_id, action, self._read_json()), 200

        challenge_match = _CHALLENGE_DETAIL.fullmatch(path)
        if challenge_match:
            if method != "GET":
                raise ServiceError("method not allowed", status=405, code="method_not_allowed")
            return {
                "challenge": service.get_challenge(unquote(challenge_match.group(1)))
            }, 200

        if path == "/api/scopes":
            if method == "GET":
                return {"scopes": service.list_scopes()}, 200
            if method == "POST":
                return {"ok": True, "scope": service.add_scope(self._read_json())}, 201
            raise ServiceError("method not allowed", status=405, code="method_not_allowed")

        scope_match = _SCOPE_DETAIL.fullmatch(path)
        if scope_match:
            if method != "DELETE":
                raise ServiceError("method not allowed", status=405, code="method_not_allowed")
            return service.delete_scope(int(scope_match.group(1))), 200

        if path == "/api/settings":
            if method == "GET":
                return {"settings": service.settings()}, 200
            if method == "PATCH":
                return {
                    "ok": True,
                    "settings": service.patch_settings(self._read_json()),
                }, 200
            raise ServiceError("method not allowed", status=405, code="method_not_allowed")

        if method == "GET" and path == "/api/audit":
            limit_raw = _query_one(query, "limit")
            try:
                limit = int(limit_raw) if limit_raw else 100
            except ValueError as exc:
                raise ServiceError("limit must be an integer", code="invalid_filter") from exc
            return {
                "audit": service.list_audit(
                    limit=limit,
                    challenge_id=_query_one(query, "challenge_id"),
                )
            }, 200
        raise ServiceError("API route not found", status=404, code="not_found")

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise ServiceError(
                "chunked request bodies are not supported",
                status=400,
                code="unsupported_transfer_encoding",
            )
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            self.close_connection = True
            raise ServiceError("invalid Content-Length", status=400) from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            self.close_connection = True
            raise ServiceError(
                f"request exceeds {MAX_REQUEST_BYTES} bytes",
                status=413,
                code="request_too_large",
            )
        if length == 0:
            return {}
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            self.close_connection = True
            raise ServiceError(
                "Content-Type must be application/json",
                status=415,
                code="unsupported_media_type",
            )
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ServiceError("invalid JSON body", code="invalid_json") from exc
        if not isinstance(value, dict):
            raise ServiceError("JSON body must be an object", code="invalid_json")
        return value

    def _send_json(self, value: Any, *, status: int = 200) -> None:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.end_headers()
        self.wfile.write(encoded)

    def _serve_static(self, request_path: str) -> None:
        decoded = unquote(request_path)
        normalized = posixpath.normpath(decoded).lstrip("/")
        if decoded.endswith("/") or not normalized:
            normalized = "index.html"
        elif normalized.startswith("static/"):
            normalized = normalized.removeprefix("static/")
        if normalized.startswith(".") or "/." in normalized:
            raise ServiceError("static file not found", status=404, code="not_found")
        root = self.server.static_dir
        candidate = (root / normalized).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ServiceError("static file not found", status=404, code="not_found") from exc
        if not candidate.is_file() and "." not in Path(normalized).name:
            candidate = root / "index.html"
        if not candidate.is_file():
            raise ServiceError("static file not found", status=404, code="not_found")
        media_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        content = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", media_type + ("; charset=utf-8" if media_type.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'",
        )
        self.send_header(
            "Cache-Control",
            "no-cache" if candidate.name == "index.html" else "public, max-age=3600",
        )
        self.end_headers()
        self.wfile.write(content)


def _query_one(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def create_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    db_path: str | Path | None = None,
    static_dir: str | Path | None = None,
    seed_demo: bool = False,
) -> CTFHTTPServer:
    resolved_db = (
        Path(db_path)
        if db_path is not None
        else Path(os.environ.get("CTF_AGENT_DB", Path.cwd() / ".ctf-agent" / "state.db"))
    )
    resolved_static = (
        Path(static_dir)
        if static_dir is not None
        else Path(__file__).resolve().parent / "static"
    )
    database = Database(resolved_db, seed_demo=seed_demo)
    return CTFHTTPServer((host, int(port)), CTFService(database), resolved_static)
