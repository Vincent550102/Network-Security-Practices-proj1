from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SignatureDatabaseError(ValueError):
    """Raised when a signature database is missing required structure."""


@dataclass(frozen=True)
class HashSignature:
    name: str
    threat_level: str
    description: str = ""


@dataclass(frozen=True)
class PatternSignature:
    name: str
    threat_level: str
    pattern: bytes
    description: str = ""


@dataclass(frozen=True)
class HeuristicRule:
    name: str
    needle: bytes
    score: int
    threat_level: str = "medium"
    description: str = ""
    case_sensitive: bool = True


@dataclass(frozen=True)
class SignatureDatabase:
    name: str
    version: str
    md5: dict[str, HashSignature]
    sha256: dict[str, HashSignature]
    patterns: tuple[PatternSignature, ...]
    heuristics: tuple[HeuristicRule, ...]
    heuristic_threshold: int

    @property
    def max_needle_length(self) -> int:
        lengths = [len(pattern.pattern) for pattern in self.patterns]
        lengths.extend(len(rule.needle) for rule in self.heuristics)
        return max(lengths, default=0)


def load_signature_database(path: str | Path) -> SignatureDatabase:
    source = Path(path)
    try:
        with source.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SignatureDatabaseError(f"Invalid JSON in {source}: {exc}") from exc
    except OSError as exc:
        raise SignatureDatabaseError(f"Cannot read signature database {source}: {exc}") from exc

    if not isinstance(raw, dict):
        raise SignatureDatabaseError("Signature database must be a JSON object.")

    hashes = _mapping(raw.get("hashes", {}), "hashes")
    heuristics = raw.get("heuristics", {})
    if heuristics == {}:
        heuristic_threshold = 5
        heuristic_rules: tuple[HeuristicRule, ...] = ()
    else:
        heuristic_map = _mapping(heuristics, "heuristics")
        heuristic_threshold = _positive_int(
            heuristic_map.get("threshold", 5), "heuristics.threshold", allow_zero=True
        )
        heuristic_rules = tuple(_parse_heuristic_rules(heuristic_map.get("rules", [])))

    return SignatureDatabase(
        name=_optional_string(raw.get("name"), "name", default="Sentinel signatures"),
        version=_optional_string(raw.get("version"), "version", default="1.0"),
        md5=_parse_hashes(hashes.get("md5", {}), "md5", expected_length=32),
        sha256=_parse_hashes(hashes.get("sha256", {}), "sha256", expected_length=64),
        patterns=tuple(_parse_patterns(raw.get("patterns", []))),
        heuristics=heuristic_rules,
        heuristic_threshold=heuristic_threshold,
    )


def _parse_hashes(raw: Any, algorithm: str, expected_length: int) -> dict[str, HashSignature]:
    entries = _mapping(raw, f"hashes.{algorithm}")
    parsed: dict[str, HashSignature] = {}
    for digest, metadata in entries.items():
        if not isinstance(digest, str):
            raise SignatureDatabaseError(f"hashes.{algorithm} keys must be strings.")
        normalized = digest.lower()
        if len(normalized) != expected_length or not _is_hex(normalized):
            raise SignatureDatabaseError(
                f"Invalid {algorithm} digest {digest!r}; expected {expected_length} hex characters."
            )
        parsed[normalized] = _parse_hash_metadata(metadata, f"hashes.{algorithm}.{digest}")
    return parsed


def _parse_hash_metadata(raw: Any, field: str) -> HashSignature:
    metadata = _mapping(raw, field)
    return HashSignature(
        name=_required_string(metadata.get("name"), f"{field}.name"),
        threat_level=_optional_string(metadata.get("threat_level"), f"{field}.threat_level", "high"),
        description=_optional_string(metadata.get("description"), f"{field}.description", ""),
    )


def _parse_patterns(raw: Any) -> list[PatternSignature]:
    entries = _list(raw, "patterns")
    parsed: list[PatternSignature] = []
    for index, entry in enumerate(entries):
        field = f"patterns[{index}]"
        metadata = _mapping(entry, field)
        parsed.append(
            PatternSignature(
                name=_required_string(metadata.get("name"), f"{field}.name"),
                threat_level=_optional_string(metadata.get("threat_level"), f"{field}.threat_level", "high"),
                pattern=_parse_needle(metadata, field),
                description=_optional_string(metadata.get("description"), f"{field}.description", ""),
            )
        )
    return parsed


def _parse_heuristic_rules(raw: Any) -> list[HeuristicRule]:
    entries = _list(raw, "heuristics.rules")
    parsed: list[HeuristicRule] = []
    for index, entry in enumerate(entries):
        field = f"heuristics.rules[{index}]"
        metadata = _mapping(entry, field)
        case_sensitive = _optional_bool(
            metadata.get("case_sensitive"), f"{field}.case_sensitive", default=True
        )
        needle = _parse_needle(metadata, field)
        if not case_sensitive:
            needle = needle.lower()
        parsed.append(
            HeuristicRule(
                name=_required_string(metadata.get("name"), f"{field}.name"),
                needle=needle,
                score=_positive_int(metadata.get("score"), f"{field}.score"),
                threat_level=_optional_string(metadata.get("threat_level"), f"{field}.threat_level", "medium"),
                description=_optional_string(metadata.get("description"), f"{field}.description", ""),
                case_sensitive=case_sensitive,
            )
        )
    return parsed


def _parse_needle(metadata: dict[str, Any], field: str) -> bytes:
    has_hex = "hex" in metadata
    has_string = "string" in metadata
    if has_hex == has_string:
        raise SignatureDatabaseError(f"{field} must define exactly one of 'hex' or 'string'.")
    if has_hex:
        raw_hex = _required_string(metadata.get("hex"), f"{field}.hex")
        try:
            needle = bytes.fromhex(raw_hex)
        except ValueError as exc:
            raise SignatureDatabaseError(f"{field}.hex is not valid hexadecimal.") from exc
    else:
        needle = _required_string(metadata.get("string"), f"{field}.string").encode("utf-8")

    if not needle:
        raise SignatureDatabaseError(f"{field} needle must not be empty.")
    return needle


def _mapping(raw: Any, field: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise SignatureDatabaseError(f"{field} must be an object.")
    return raw


def _list(raw: Any, field: str) -> list[Any]:
    if not isinstance(raw, list):
        raise SignatureDatabaseError(f"{field} must be an array.")
    return raw


def _required_string(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or raw == "":
        raise SignatureDatabaseError(f"{field} must be a non-empty string.")
    return raw


def _optional_string(raw: Any, field: str, default: str) -> str:
    if raw is None:
        return default
    if not isinstance(raw, str):
        raise SignatureDatabaseError(f"{field} must be a string.")
    return raw


def _optional_bool(raw: Any, field: str, default: bool) -> bool:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        raise SignatureDatabaseError(f"{field} must be true or false.")
    return raw


def _positive_int(raw: Any, field: str, allow_zero: bool = False) -> int:
    if not isinstance(raw, int):
        raise SignatureDatabaseError(f"{field} must be an integer.")
    if allow_zero:
        if raw < 0:
            raise SignatureDatabaseError(f"{field} must be zero or greater.")
    elif raw <= 0:
        raise SignatureDatabaseError(f"{field} must be greater than zero.")
    return raw


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
    except ValueError:
        return False
    return True
