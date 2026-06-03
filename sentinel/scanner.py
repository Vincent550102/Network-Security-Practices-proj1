from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .signatures import HeuristicRule, PatternSignature, SignatureDatabase


THREAT_RANK = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class Scanner:
    def __init__(
        self,
        database: SignatureDatabase,
        *,
        chunk_size: int = 1024 * 1024,
        max_file_size_bytes: int = 100 * 1024 * 1024,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than zero")
        if max_file_size_bytes <= 0:
            raise ValueError("max_file_size_bytes must be greater than zero")
        self.database = database
        self.chunk_size = chunk_size
        self.max_file_size_bytes = max_file_size_bytes

    def scan(self, target: str | Path, *, signature_source: str | Path | None = None) -> dict[str, Any]:
        target_path = Path(target)
        started_at = _now_iso()
        started = time.perf_counter()
        summary = {
            "scanned_files": 0,
            "clean_files": 0,
            "infected_files": 0,
            "suspicious_files": 0,
            "skipped_files": 0,
            "errors": 0,
        }
        findings: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        skipped: list[dict[str, str]] = []

        for item_type, path, message in self._iter_scan_items(target_path):
            if item_type == "error":
                summary["errors"] += 1
                errors.append({"path": str(path), "error": message or "Unknown error"})
                continue
            if item_type == "skipped":
                summary["skipped_files"] += 1
                skipped.append({"path": str(path), "reason": message or "Skipped"})
                continue

            try:
                file_result = self._scan_file(path)
            except OSError as exc:
                summary["errors"] += 1
                errors.append({"path": str(path), "error": str(exc)})
                continue

            if file_result["status"] == "skipped":
                summary["skipped_files"] += 1
                skipped.append({"path": file_result["path"], "reason": file_result["reason"]})
                continue

            summary["scanned_files"] += 1
            status = file_result["status"]
            if status == "infected":
                summary["infected_files"] += 1
                findings.append(file_result)
            elif status == "suspicious":
                summary["suspicious_files"] += 1
                findings.append(file_result)
            else:
                summary["clean_files"] += 1

        return {
            "scanner": "Sentinel",
            "generated_at": _now_iso(),
            "started_at": started_at,
            "duration_seconds": round(time.perf_counter() - started, 6),
            "target": str(target_path),
            "signature_database": str(signature_source) if signature_source is not None else None,
            "signature_database_name": self.database.name,
            "signature_database_version": self.database.version,
            "summary": summary,
            "findings": findings,
            "errors": errors,
            "skipped": skipped,
        }

    def _iter_scan_items(self, target: Path):
        if not target.exists():
            yield ("error", target, "Target does not exist")
            return
        if target.is_symlink():
            yield ("skipped", target, "Symlinks are skipped")
            return
        if target.is_file():
            yield ("file", target, None)
            return
        if not target.is_dir():
            yield ("error", target, "Target is not a regular file or directory")
            return

        for root, directories, files in os.walk(target, followlinks=False):
            root_path = Path(root)
            safe_directories = []
            for directory in sorted(directories):
                directory_path = root_path / directory
                if directory_path.is_symlink():
                    yield ("skipped", directory_path, "Symlinked directory skipped")
                else:
                    safe_directories.append(directory)
            directories[:] = safe_directories

            for filename in sorted(files):
                path = root_path / filename
                if path.is_symlink():
                    yield ("skipped", path, "Symlinked file skipped")
                else:
                    yield ("file", path, None)

    def _scan_file(self, path: Path) -> dict[str, Any]:
        size = path.stat().st_size
        if size > self.max_file_size_bytes:
            return {
                "path": str(path),
                "status": "skipped",
                "reason": f"File is larger than max_file_size_bytes={self.max_file_size_bytes}",
            }

        md5_hasher = hashlib.md5()
        sha256_hasher = hashlib.sha256()
        pattern_hits: set[int] = set()
        heuristic_hits: set[int] = set()
        carry = b""
        max_needle_length = self.database.max_needle_length

        with path.open("rb") as handle:
            while True:
                chunk = handle.read(self.chunk_size)
                if not chunk:
                    break

                md5_hasher.update(chunk)
                sha256_hasher.update(chunk)

                window = carry + chunk
                self._collect_pattern_hits(window, pattern_hits)
                self._collect_heuristic_hits(window, heuristic_hits)

                if max_needle_length > 1:
                    carry = window[-(max_needle_length - 1) :]
                else:
                    carry = b""

        md5_digest = md5_hasher.hexdigest()
        sha256_digest = sha256_hasher.hexdigest()
        matches: list[dict[str, Any]] = []
        signature_match_count = 0

        if sha256_digest in self.database.sha256:
            signature = self.database.sha256[sha256_digest]
            matches.append(
                _match("sha256", signature.name, signature.threat_level, sha256_digest)
            )
            signature_match_count += 1
        if md5_digest in self.database.md5:
            signature = self.database.md5[md5_digest]
            matches.append(_match("md5", signature.name, signature.threat_level, md5_digest))
            signature_match_count += 1

        for index in sorted(pattern_hits):
            signature = self.database.patterns[index]
            matches.append(
                _match("pattern", signature.name, signature.threat_level, signature.pattern.hex())
            )
            signature_match_count += 1

        heuristic_score = 0
        for index in sorted(heuristic_hits):
            rule = self.database.heuristics[index]
            heuristic_score += rule.score
            matches.append(
                _match(
                    "heuristic",
                    rule.name,
                    rule.threat_level,
                    rule.needle.decode("utf-8", errors="replace"),
                    score=rule.score,
                )
            )

        if signature_match_count > 0:
            status = "infected"
        elif heuristic_score >= self.database.heuristic_threshold:
            status = "suspicious"
        else:
            status = "clean"

        return {
            "path": str(path),
            "status": status,
            "threat_level": _highest_threat(match["threat_level"] for match in matches),
            "size_bytes": size,
            "md5": md5_digest,
            "sha256": sha256_digest,
            "heuristic_score": heuristic_score,
            "heuristic_threshold": self.database.heuristic_threshold,
            "matches": matches,
        }

    def _collect_pattern_hits(self, window: bytes, hits: set[int]) -> None:
        for index, signature in enumerate(self.database.patterns):
            if index not in hits and _contains_pattern(window, signature):
                hits.add(index)

    def _collect_heuristic_hits(self, window: bytes, hits: set[int]) -> None:
        lowercase_window: bytes | None = None
        for index, rule in enumerate(self.database.heuristics):
            if index in hits:
                continue
            haystack = window
            if not rule.case_sensitive:
                if lowercase_window is None:
                    lowercase_window = window.lower()
                haystack = lowercase_window
            if _contains_heuristic(haystack, rule):
                hits.add(index)


def _contains_pattern(window: bytes, signature: PatternSignature) -> bool:
    return signature.pattern in window


def _contains_heuristic(window: bytes, rule: HeuristicRule) -> bool:
    return rule.needle in window


def _match(
    match_type: str,
    name: str,
    threat_level: str,
    detail: str,
    *,
    score: int | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": match_type,
        "name": name,
        "threat_level": threat_level,
        "detail": detail,
    }
    if score is not None:
        result["score"] = score
    return result


def _highest_threat(levels) -> str:
    highest = "none"
    for level in levels:
        if THREAT_RANK.get(level, 0) > THREAT_RANK.get(highest, 0):
            highest = level
    return highest


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
