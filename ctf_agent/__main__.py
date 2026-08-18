"""Command-line entry point for CTF Agent."""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from pathlib import Path

from . import VERSION
from .benchmark import (
    aggregate_metrics,
    blind_payload,
    load_manifest,
    load_results,
    render_report,
    validate_manifest,
    validate_results,
)
from .cryptohack_archive import (
    ARCHIVE_URL,
    download_static_files,
    extract_zip_safely,
    fetch_archive_html,
    preflight_archives,
    triage_inventory,
    write_inventory,
)
from .http import create_server
from .playbooks import (
    get_playbook,
    list_playbooks,
    serialise,
    suggest_playbooks,
    validate_playbooks,
)
from .sandbox import DEFAULT_IMAGE, DockerStaticSandbox, SandboxError
from .service import CTFService
from .storage import Database


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-agent",
        description="Local, CTF-only orchestration dashboard",
    )
    parser.add_argument("--version", action="version", version=VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="serve the dashboard and JSON API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--db", type=Path, default=None)
    serve_demo = serve.add_mutually_exclusive_group()
    serve_demo.add_argument(
        "--demo",
        dest="seed_demo",
        action="store_true",
        help="seed the database with demonstration challenges",
    )
    serve_demo.add_argument(
        "--no-demo",
        dest="seed_demo",
        action="store_false",
        help="do not seed demonstration challenges (default; retained for compatibility)",
    )
    serve.set_defaults(seed_demo=False)
    health = subparsers.add_parser("health", help="check the local SQLite store")
    health.add_argument("--db", type=Path, default=None)
    health_demo = health.add_mutually_exclusive_group()
    health_demo.add_argument(
        "--demo",
        dest="seed_demo",
        action="store_true",
        help="seed the database with demonstration challenges before checking it",
    )
    health_demo.add_argument(
        "--no-demo",
        dest="seed_demo",
        action="store_false",
        help="do not seed demonstration challenges (default; retained for compatibility)",
    )
    health.set_defaults(seed_demo=False)
    sandbox = subparsers.add_parser(
        "sandbox-inspect", help="run an approved read-only artifact inspection in Docker"
    )
    sandbox.add_argument("--workspace", type=Path, required=True)
    sandbox.add_argument("--artifact", type=Path, required=True)
    sandbox.add_argument(
        "--action",
        choices=(
            "identify",
            "archive_list",
            "elf_headers",
            "elf_symbols",
            "strings",
            "object_headers",
        ),
        required=True,
    )
    sandbox.add_argument("--image", default=DEFAULT_IMAGE)
    sandbox.add_argument("--timeout", type=int, default=8)
    sandbox.add_argument(
        "--approve",
        action="store_true",
        help="explicitly approve this bounded local container action",
    )
    playbooks = subparsers.add_parser(
        "playbooks", help="list reusable offline crypto workflows (read-only)"
    )
    playbooks.add_argument("playbook", nargs="?", help="show one route by id")
    playbooks.add_argument("--category", help="filter by family, for example rsa")
    playbooks.add_argument("--search", help="search route names, evidence, and signals")
    playbooks.add_argument(
        "--suggest",
        metavar="TEXT",
        help="rank routes from supplied challenge text (hint only)",
    )
    playbooks.add_argument(
        "--json", action="store_true", help="emit machine-readable route records"
    )
    playbooks.add_argument(
        "--validate", action="store_true", help="check that indexed local scripts exist"
    )
    benchmark = subparsers.add_parser(
        "benchmark", help="validate blind crypto benchmark data and render metrics"
    )
    benchmark_subparsers = benchmark.add_subparsers(dest="benchmark_action", required=True)
    benchmark_validate = benchmark_subparsers.add_parser(
        "validate", help="validate a manifest and optionally require 30 entries"
    )
    benchmark_validate.add_argument("--manifest", type=Path, required=True)
    benchmark_validate.add_argument("--root", type=Path, default=Path.cwd())
    benchmark_validate.add_argument("--complete", action="store_true")
    benchmark_payload = benchmark_subparsers.add_parser(
        "payload", help="emit one blind challenge payload without hidden metadata"
    )
    benchmark_payload.add_argument("--manifest", type=Path, required=True)
    benchmark_payload.add_argument("--root", type=Path, default=Path.cwd())
    benchmark_payload.add_argument("--id", required=True, dest="challenge_id")
    benchmark_report = benchmark_subparsers.add_parser(
        "report", help="aggregate JSONL results and render BENCHMARK_REPORT.md"
    )
    benchmark_report.add_argument("--manifest", type=Path, required=True)
    benchmark_report.add_argument("--results", type=Path, required=True)
    benchmark_report.add_argument("--output", type=Path, required=True)
    benchmark_report.add_argument("--root", type=Path, default=Path.cwd())
    archive = subparsers.add_parser(
        "archive", help="inventory the official CryptoHack CTF Archive index"
    )
    archive_subparsers = archive.add_subparsers(dest="archive_action", required=True)
    archive_inventory = archive_subparsers.add_parser(
        "inventory", help="parse an official index page without contacting challenge services"
    )
    archive_source = archive_inventory.add_mutually_exclusive_group(required=True)
    archive_source.add_argument("--fetch", action="store_true", help="fetch the canonical official index")
    archive_source.add_argument("--html", type=Path, help="use a previously saved official index")
    archive_inventory.add_argument("--output", type=Path, required=True)
    archive_download = archive_subparsers.add_parser(
        "download", help="download linked official static files without extracting them"
    )
    archive_download.add_argument("--inventory", type=Path, required=True)
    archive_download.add_argument("--output-dir", type=Path, required=True)
    archive_download.add_argument("--manifest", type=Path, required=True)
    archive_preflight = archive_subparsers.add_parser(
        "preflight", help="list ZIP members and reject unsafe paths without extraction"
    )
    archive_preflight.add_argument("--root", type=Path, required=True)
    archive_preflight.add_argument("--output", type=Path, required=True)
    archive_triage = archive_subparsers.add_parser(
        "triage", help="add deterministic route hints to a local inventory"
    )
    archive_triage.add_argument("--inventory", type=Path, required=True)
    archive_triage.add_argument("--output", type=Path, required=True)
    archive_extract = archive_subparsers.add_parser(
        "extract", help="extract selected preflighted ZIP members with hard caps"
    )
    archive_extract.add_argument("--archive", type=Path, required=True)
    archive_extract.add_argument("--output-dir", type=Path, required=True)
    archive_extract.add_argument("--member", action="append", dest="members")
    archive_extract.add_argument("--manifest", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "serve":
        if not 0 <= args.port <= 65_535:
            print("port must be between 0 and 65535", file=sys.stderr)
            return 2
        server = create_server(
            host=args.host,
            port=args.port,
            db_path=args.db,
            seed_demo=args.seed_demo,
        )
        host, port = server.server_address[:2]
        print(f"CTF Agent {VERSION} listening on http://{host}:{port}", flush=True)
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            print("\nStopping CTF Agent.", flush=True)
        finally:
            server.shutdown()
            server.server_close()
        return 0
    if args.command == "sandbox-inspect":
        try:
            result = DockerStaticSandbox(
                args.workspace, image=args.image
            ).inspect(
                args.artifact,
                action=args.action,
                timeout_seconds=args.timeout,
                operator_approved=args.approve,
            )
        except SandboxError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
        return 0 if result.exit_code == 0 and not result.timed_out else 1
    if args.command == "playbooks":
        if args.validate:
            missing = validate_playbooks()
            if missing:
                print("missing indexed scripts:")
                print("\n".join(missing))
                return 1
            print(f"validated {len(list_playbooks())} crypto playbooks")
            if not args.playbook and not args.search and not args.category and not args.suggest:
                return 0

        if args.playbook:
            try:
                selected = get_playbook(args.playbook)
            except KeyError as exc:
                print(str(exc), file=sys.stderr)
                return 2
            if args.json:
                print(json.dumps(selected.as_dict(), ensure_ascii=False, indent=2))
            else:
                print(f"{selected.id} [{selected.family}; {selected.status}]")
                print(f"Title: {selected.title}")
                print(f"Evidence: {selected.evidence}")
                print(f"First check: {selected.first_check}")
                print(f"Verify: {selected.verify}")
                print(f"Command: {selected.command()}")
            return 0

        if args.suggest is not None:
            suggestions = suggest_playbooks(args.suggest)
            if args.json:
                print(
                    json.dumps(
                        [dict(playbook=playbook.as_dict(), score=score) for playbook, score in suggestions],
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            elif suggestions:
                for playbook, score in suggestions:
                    print(f"{score}  {playbook.id:<32} {playbook.title} [{playbook.status}]")
            else:
                print("No evidence-matching route; keep triage deterministic and inspect the source.")
            return 0

        records = list_playbooks(category=args.category, search=args.search)
        if args.json:
            print(json.dumps(serialise(records), ensure_ascii=False, indent=2))
            return 0
        if not records:
            print("No matching crypto playbooks.")
            return 0
        print(f"{'ID':<34} {'FAMILY':<12} {'MODE':<15} TITLE")
        print("-" * 92)
        for playbook in records:
            print(
                f"{playbook.id:<34} {playbook.family:<12} "
                f"{playbook.status:<15} {playbook.title}"
            )
        print("\nUse `ctf-agent playbooks ROUTE_ID` for evidence, verification, and a command template.")
        return 0
    if args.command == "benchmark":
        try:
            manifest = load_manifest(args.manifest)
        except (OSError, ValueError) as exc:
            print(f"manifest error: {exc}", file=sys.stderr)
            return 2
        if args.benchmark_action == "validate":
            errors = validate_manifest(manifest, args.root, require_complete=args.complete)
            if errors:
                print("\n".join(errors), file=sys.stderr)
                return 1
            print(f"manifest valid: {len(manifest.challenges)} challenge(s)")
            return 0
        if args.benchmark_action == "payload":
            errors = validate_manifest(manifest, args.root)
            if errors:
                print("manifest is not ready:", file=sys.stderr)
                print("\n".join(errors), file=sys.stderr)
                return 1
            try:
                print(json.dumps(blind_payload(manifest, args.challenge_id, args.root), ensure_ascii=False, indent=2))
            except (KeyError, OSError, ValueError) as exc:
                print(f"payload error: {exc}", file=sys.stderr)
                return 2
            return 0
        try:
            results = load_results(args.results)
        except (OSError, ValueError) as exc:
            print(f"results error: {exc}", file=sys.stderr)
            return 2
        errors = validate_manifest(manifest, args.root)
        errors.extend(validate_results(results, manifest))
        if errors:
            print("benchmark data is not valid:", file=sys.stderr)
            print("\n".join(errors), file=sys.stderr)
            return 1
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(render_report(manifest, results), encoding="utf-8")
        except OSError as exc:
            print(f"report error: {exc}", file=sys.stderr)
            return 2
        metrics = aggregate_metrics(results, manifest)
        print(json.dumps(metrics, ensure_ascii=False, indent=2))
        return 0
    if args.command == "archive":
        if args.archive_action == "inventory":
            try:
                source = fetch_archive_html(ARCHIVE_URL) if args.fetch else args.html.read_text(encoding="utf-8")
                payload = write_inventory(args.output, source)
            except (OSError, ValueError) as exc:
                print(f"archive inventory error: {exc}", file=sys.stderr)
                return 2
            print(json.dumps(payload["summary"], ensure_ascii=False, indent=2))
            print(f"wrote {len(payload['challenges'])} challenge records to {args.output}")
            return 0
        if args.archive_action == "download":
            try:
                inventory_payload = json.loads(args.inventory.read_text(encoding="utf-8"))
                records = inventory_payload["challenges"]
                result = download_static_files(records, args.output_dir)
                args.manifest.parent.mkdir(parents=True, exist_ok=True)
                args.manifest.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "source_inventory": str(args.inventory),
                            "policy": "official static files only; no extraction or execution",
                            **result,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                print(f"archive download error: {exc}", file=sys.stderr)
                return 2
            print(json.dumps({"total_files": result["total_files"], "total_bytes": result["total_bytes"]}, indent=2))
            print(f"wrote manifest {args.manifest}")
            return 0
        if args.archive_action == "preflight":
            try:
                reports = preflight_archives(args.root)
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "policy": "ZIP central-directory metadata only; no extraction or execution",
                            "archives": reports,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                print(f"archive preflight error: {exc}", file=sys.stderr)
                return 2
            print(json.dumps({"archives": len(reports), "members": sum(item["member_count"] for item in reports)}, indent=2))
            print(f"wrote preflight report {args.output}")
            return 0
        if args.archive_action == "triage":
            try:
                inventory_payload = json.loads(args.inventory.read_text(encoding="utf-8"))
                records = inventory_payload["challenges"]
                report = {
                    "schema_version": 1,
                    "source_inventory": str(args.inventory),
                    "policy": "deterministic route hints only; no solving or remote access",
                    "challenges": triage_inventory(records),
                }
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                print(f"archive triage error: {exc}", file=sys.stderr)
                return 2
            print(json.dumps({"challenges": len(report["challenges"])}, indent=2))
            print(f"wrote triage report {args.output}")
            return 0
        if args.archive_action == "extract":
            try:
                result = extract_zip_safely(
                    args.archive,
                    args.output_dir,
                    members=set(args.members) if args.members else None,
                )
                args.manifest.parent.mkdir(parents=True, exist_ok=True)
                args.manifest.write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "policy": "selected ZIP members after full preflight; bounded extraction only",
                            **result,
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                print(f"archive extract error: {exc}", file=sys.stderr)
                return 2
            print(json.dumps({"total_files": result["total_files"], "total_bytes": result["total_bytes"]}, indent=2))
            print(f"wrote extraction manifest {args.manifest}")
            return 0
    health_db = args.db or Path(
        os.environ.get("CTF_AGENT_DB", Path.cwd() / ".ctf-agent" / "state.db")
    )
    database = Database(health_db, seed_demo=args.seed_demo)
    try:
        print(
            json.dumps(
                CTFService(database).health(),
                indent=2,
                ensure_ascii=False,
            )
        )
    finally:
        database.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
