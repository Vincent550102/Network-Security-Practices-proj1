from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.scanner import Scanner
from sentinel.signatures import load_signature_database


ROOT = Path(__file__).resolve().parents[1]
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = load_signature_database(ROOT / "signatures.json")

    def test_sha256_and_md5_hash_match_marks_file_infected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "eicar.com"
            target.write_bytes(EICAR)

            report = Scanner(self.database).scan(target)

        self.assertEqual(report["summary"]["infected_files"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["status"], "infected")
        self.assertIn("sha256", {match["type"] for match in finding["matches"]})
        self.assertIn("md5", {match["type"] for match in finding["matches"]})

    def test_hex_pattern_match_across_chunk_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "split-pattern.bin"
            target.write_bytes(b"A" * 10 + EICAR + b"Z" * 10)

            report = Scanner(self.database, chunk_size=16).scan(target)

        self.assertEqual(report["summary"]["infected_files"], 1)
        finding = report["findings"][0]
        self.assertIn("pattern", {match["type"] for match in finding["matches"]})

    def test_heuristic_score_marks_file_suspicious(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "api-notes.txt"
            target.write_text(
                "VirtualAlloc WriteProcessMemory CreateRemoteThread",
                encoding="utf-8",
            )

            report = Scanner(self.database).scan(target)

        self.assertEqual(report["summary"]["suspicious_files"], 1)
        finding = report["findings"][0]
        self.assertEqual(finding["status"], "suspicious")
        self.assertGreaterEqual(finding["heuristic_score"], 5)

    def test_empty_folder_has_zero_scanned_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = Scanner(self.database).scan(Path(directory))

        self.assertEqual(report["summary"]["scanned_files"], 0)
        self.assertEqual(report["findings"], [])

    def test_nested_folder_finds_hidden_eicar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "a" / "b" / "c"
            nested.mkdir(parents=True)
            (root / "clean.txt").write_text("hello", encoding="utf-8")
            (nested / "eicar.com").write_bytes(EICAR)

            report = Scanner(self.database).scan(root)

        self.assertEqual(report["summary"]["scanned_files"], 2)
        self.assertEqual(report["summary"]["infected_files"], 1)
        self.assertEqual(report["summary"]["clean_files"], 1)

    def test_large_file_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "large.bin"
            target.write_bytes(b"A" * 32)

            report = Scanner(self.database, max_file_size_bytes=8).scan(target)

        self.assertEqual(report["summary"]["skipped_files"], 1)
        self.assertEqual(report["summary"]["scanned_files"], 0)

    def test_missing_target_is_reported_as_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"

            report = Scanner(self.database).scan(missing)

        self.assertEqual(report["summary"]["errors"], 1)
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
