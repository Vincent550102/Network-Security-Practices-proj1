from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .reporting import format_text_report, write_json_report, write_text_report
from .scanner import Scanner
from .signatures import SignatureDatabaseError, load_signature_database


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args)

    parser.print_help()
    return 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel signature-based virus scanner.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Scan a file or directory.")
    scan.add_argument("--target", required=True, help="File or directory to scan.")
    scan.add_argument("--signatures", required=True, help="Path to signature JSON database.")
    scan.add_argument("--output", required=True, help="Path for the JSON report.")
    scan.add_argument("--text-output", help="Optional path for a human-readable text report.")
    scan.add_argument(
        "--max-file-size-mb",
        type=_positive_float,
        default=100.0,
        help="Skip files larger than this size in MiB. Default: 100.",
    )
    scan.add_argument(
        "--chunk-size-kb",
        type=_positive_int,
        default=1024,
        help="Read files in chunks of this size in KiB. Default: 1024.",
    )

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    signatures_path = Path(args.signatures)
    try:
        database = load_signature_database(signatures_path)
    except SignatureDatabaseError as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner(
        database,
        chunk_size=args.chunk_size_kb * 1024,
        max_file_size_bytes=int(args.max_file_size_mb * 1024 * 1024),
    )
    report = scanner.scan(Path(args.target), signature_source=signatures_path)
    write_json_report(report, args.output)
    if args.text_output:
        write_text_report(report, args.text_output)

    print(format_text_report(report), end="")
    return 0


def _positive_float(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return value


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value
