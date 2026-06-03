from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json_report(report: dict[str, Any], output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")


def write_text_report(report: dict[str, Any], output: str | Path) -> None:
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write(format_text_report(report))


def format_text_report(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "Sentinel Scan Report",
        "====================",
        f"Generated: {report['generated_at']}",
        f"Target: {report['target']}",
        f"Signature DB: {report.get('signature_database') or 'not recorded'}",
        f"Duration: {report['duration_seconds']} seconds",
        "",
        "Summary",
        "-------",
        f"Scanned files: {summary['scanned_files']}",
        f"Clean files: {summary['clean_files']}",
        f"Infected files: {summary['infected_files']}",
        f"Suspicious files: {summary['suspicious_files']}",
        f"Skipped files: {summary['skipped_files']}",
        f"Errors: {summary['errors']}",
        "",
        "Findings",
        "--------",
    ]

    if not report["findings"]:
        lines.append("No infected or suspicious files were found.")
    else:
        for finding in report["findings"]:
            lines.append(
                f"[{finding['status'].upper()}] {finding['path']} "
                f"({finding['threat_level']}, heuristic score {finding['heuristic_score']})"
            )
            for match in finding["matches"]:
                score = f", score {match['score']}" if "score" in match else ""
                lines.append(
                    f"  - {match['type']}: {match['name']} "
                    f"({match['threat_level']}{score})"
                )
                lines.append(f"    detail: {match['detail']}")

    if report["skipped"]:
        lines.extend(["", "Skipped", "-------"])
        for item in report["skipped"]:
            lines.append(f"{item['path']}: {item['reason']}")

    if report["errors"]:
        lines.extend(["", "Errors", "------"])
        for item in report["errors"]:
            lines.append(f"{item['path']}: {item['error']}")

    lines.append("")
    return "\n".join(lines)
