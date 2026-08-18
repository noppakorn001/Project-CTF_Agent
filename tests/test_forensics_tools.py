from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import zlib
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ForensicsToolTests(unittest.TestCase):
    def test_tshark_triage_is_offline_and_provenance_backed(self) -> None:
        mod = load("tshark_tool", "tools/forensics/tshark_triage.py")
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.pcapng"
            capture.write_bytes(b"fixture-pcap")

            class Completed:
                returncode = 0
                stdout = "1\t0\tTCP\t10.0.0.1\t10.0.0.2\t0\tdata\n"
                stderr = ""

            with patch.object(mod.shutil, "which", return_value="/usr/bin/tshark"):
                with patch.object(mod.subprocess, "run", return_value=Completed()) as run:
                    report = mod.triage(capture, display_filter="tcp.stream == 0")
            command = run.call_args.args[0]
            self.assertIn("-r", command)
            self.assertNotIn("-i", command)
            self.assertNotIn("-w", command)
            self.assertEqual(report["returncode"], 0)
            self.assertEqual(report["sha256"], hashlib.sha256(b"fixture-pcap").hexdigest())

    def test_tshark_triage_rejects_unsafe_field(self) -> None:
        mod = load("tshark_tool_bad_field", "tools/forensics/tshark_triage.py")
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "capture.pcap"
            capture.write_bytes(b"fixture-pcap")
            with patch.object(mod.shutil, "which", return_value="/usr/bin/tshark"):
                with self.assertRaisesRegex(ValueError, "unsafe field"):
                    mod.triage(capture, fields=("frame.number --bad",))

    def test_binwalk_gate_uses_identification_only(self) -> None:
        mod = load("binwalk_gate", "tools/forensics/binwalk_gate.py")
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "firmware.bin"
            artifact.write_bytes(b"\x7fELF" + b"fixture")

            class Completed:
                returncode = 0
                stdout = "0 ELF header\n"
                stderr = ""

            with patch.object(mod.subprocess, "run", return_value=Completed()) as run:
                code, stdout, stderr = mod.run_identification("/usr/bin/binwalk", artifact)
            command = run.call_args.args[0]
            self.assertEqual(command[1], "--signature")
            self.assertNotIn("-e", command)
            self.assertEqual(code, 0)
            self.assertEqual(stdout, "0 ELF header\n")
            self.assertEqual(stderr, "")

    def test_dns_reassembly_orders_and_validates_suffix(self) -> None:
        mod = load("dns_tool", "tools/forensics/reassemble_dns_hex.py")
        out = mod.reassemble(
            [
                "2\t4344.totallynotmalicious.xyz",
                "1\t4243.totallynotmalicious.xyz",
            ],
            ".totallynotmalicious.xyz",
        )
        self.assertEqual(out, b"BCCD")


    def test_dns_reassembly_rejects_non_hex(self) -> None:
        mod = load("dns_tool_bad", "tools/forensics/reassemble_dns_hex.py")
        with self.assertRaisesRegex(ValueError, "hex"):
            mod.reassemble(["1\tzz.totallynotmalicious.xyz"], ".totallynotmalicious.xyz")


    def test_zlib_scan_records_decoded_hash(self) -> None:
        mod = load("zlib_tool", "tools/forensics/scan_zlib_members.py")
        plain = b"flag-shaped lead is not proof"
        blob = b"noise" + zlib.compress(plain) + b"tail"
        rows = mod.scan(blob)
        self.assertTrue(rows)
        self.assertEqual(rows[0]["length"], len(plain))
        self.assertEqual(rows[0]["sha256"], hashlib.sha256(plain).hexdigest())
