from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from ctf_agent.__main__ import main
from ctf_agent.cryptohack_archive import (
    download_static_files,
    extract_zip_safely,
    parse_archive_html,
    summary,
    triage_inventory,
    write_inventory,
)


FIXTURE = '''
<span class="stage" data-stage="ctf-archive-2024">
<li class="challenge" data-stage="ctf-archive-2024">
<div id="header-demo" data-challenge="demo-challenge"><div class="challenge-text truncate">Demo Challenge (Test CTF)</div></div>
<div class="collapsible-body"><div class="challengeDescription">
An RSA fixture with a bounded relation.<br /><br />Challenge contributed by <a href="/user/x">x</a><br /><br />Connect at <code>archive.cryptohack.org 12345</code><br /><br /><b>Challenge files:</b><br /> - <a href="/static/challenges/demo.py" download>demo.py</a><br />
</div></div>
</li>
</span>
'''


class CryptoHackArchiveTests(unittest.TestCase):
    def test_parser_keeps_scope_and_omits_solution_metadata(self) -> None:
        records = parse_archive_html(FIXTURE)
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.challenge_id, "demo-challenge")
        self.assertEqual(record.year, 2024)
        self.assertEqual(record.title, "Demo Challenge (Test CTF)")
        self.assertEqual(record.description, "An RSA fixture with a bounded relation.")
        self.assertEqual(record.remote_host, "archive.cryptohack.org")
        self.assertEqual(record.remote_port, 12345)
        self.assertEqual(record.files[0].url, "https://cryptohack.org/static/challenges/demo.py")
        self.assertNotIn("solves", record.as_dict())
        self.assertNotIn("solutions", record.as_dict())

    def test_summary_and_inventory_output(self) -> None:
        records = parse_archive_html(FIXTURE)
        self.assertEqual(summary([records[0].as_dict()]), {"total": 1, "years": {"2024": 1}, "offline": 0, "remote": 1, "files": 1})
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "index.json"
            payload = write_inventory(output, FIXTURE)
            self.assertTrue(output.is_file())
            self.assertEqual(json.loads(output.read_text())["summary"]["total"], 1)
            self.assertEqual(payload["policy"], "index-only; no solution metadata; no remote challenge connections")

    def test_cli_uses_local_html_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "archive.html"
            output = root / "index.json"
            source.write_text(FIXTURE, encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                self.assertEqual(
                    main(["archive", "inventory", "--html", str(source), "--output", str(output)]),
                    0,
                )
            self.assertIn('"total": 1', stdout.getvalue())

    def test_download_empty_inventory_is_local_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = download_static_files([], Path(directory) / "files")
            self.assertEqual(result["total_files"], 0)
            self.assertEqual(result["total_bytes"], 0)

    def test_preflight_rejects_path_traversal_without_extracting(self) -> None:
        from ctf_agent.cryptohack_archive import preflight_archives

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "bad.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape.txt", b"no")
            with self.assertRaises(ValueError):
                preflight_archives(root)
            self.assertFalse((root.parent / "escape.txt").exists())

    def test_triage_is_hint_only(self) -> None:
        record = parse_archive_html(FIXTURE)[0].as_dict()
        result = triage_inventory([record])
        self.assertEqual(result[0]["challenge_id"], "demo-challenge")
        self.assertTrue(result[0]["remote"])
        self.assertTrue(any(item["id"] == "rsa/exact-low-exponent" for item in result[0]["route_hints"]))

    def test_extract_selected_member_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "safe.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("nested/input.txt", b"bounded")
                handle.writestr("other.txt", b"untouched")
            result = extract_zip_safely(
                archive,
                root / "out",
                members={"nested/input.txt"},
            )
            self.assertEqual(result["total_files"], 1)
            self.assertEqual((root / "out/nested/input.txt").read_bytes(), b"bounded")
            self.assertFalse((root / "out/other.txt").exists())


if __name__ == "__main__":
    unittest.main()
