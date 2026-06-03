# Project Report: Sentinel Signature-Based Virus Scanner

## 1. Overview

Sentinel is a functional signature-based virus scanner. Its goal is to scan a target directory, compare file content against known malware signatures, apply basic heuristic rules, and generate a security report. The scanner is designed for safe demonstrations: it only reads files and never executes any scanned file.

The demo uses the EICAR test file, a standard harmless antivirus test string, hidden in a nested folder. Sentinel detects it through both hash signatures and a byte pattern signature.

## 2. Signature Database Design

The signature database is stored in JSON because it is human-readable, easy to version-control, and supported by Python's standard library. It contains three major sections:

- `hashes`: exact MD5 and SHA256 signatures for known files.
- `patterns`: byte patterns encoded as hexadecimal strings.
- `heuristics`: suspicious strings with scores and threat levels.

Hash signatures are stored as hash maps:

```json
{
  "sha256": {
    "275a...fd0f": {
      "name": "EICAR-Test-File",
      "threat_level": "high"
    }
  }
}
```

A hash map is appropriate because the scanner calculates a file digest once and then needs a fast membership test. Average lookup time is O(1), which keeps the exact-signature phase efficient even when the database grows.

## 3. Scanning Engine

Sentinel recursively traverses the target directory and scans only regular files. Symlinks are skipped to avoid loops or unintended traversal outside the target tree.

For each file, Sentinel:

1. Reads bytes in chunks.
2. Updates MD5 and SHA256 hash contexts.
3. Searches for known byte patterns.
4. Searches for heuristic strings.
5. Assigns a final status: `clean`, `suspicious`, or `infected`.

Chunk-based reading prevents large files from being loaded into memory all at once. The scanner keeps a small carry-over buffer between chunks so signatures split across chunk boundaries can still be detected.

## 4. Heuristic Analysis

Heuristic analysis is used to flag files that do not match a known malware signature but contain suspicious indicators. The current rules look for strings commonly associated with Windows process injection or command hiding:

- `CreateRemoteThread`
- `WriteProcessMemory`
- `VirtualAlloc`
- `-EncodedCommand`

Each rule contributes a score. If the total score reaches the configured threshold, the file is marked as `suspicious`. This is intentionally simple and explainable for the project demo.

## 5. Reporting

Sentinel outputs a JSON report and an optional text report. The JSON report includes:

- generated timestamp
- scanned target
- scan duration
- summary counts
- infected and suspicious findings
- skipped files
- scan errors

Each finding includes the path, status, threat level, hash values, heuristic score, and matched signatures.

## 6. Bloom Filter Discussion

A Bloom Filter could be added as an optimization for very large signature databases. It would provide a memory-efficient pre-check before hash map lookup. However, Bloom Filters can produce false positives, so the scanner would still need the hash map to confirm exact matches. For this project, a direct hash map is simpler, exact, and fast enough for the expected database size.

## 7. Limitations

Sentinel is a teaching project, not a production antivirus engine. It does not unpack compressed files, emulate code, detect polymorphic malware, or inspect PE headers deeply. Its purpose is to demonstrate the core ideas behind signature matching, safe scanning, heuristic scoring, and security report generation.

## 8. Demonstration Plan

Run:

```bash
python3 -m sentinel scan \
  --target samples \
  --signatures signatures.json \
  --output reports/report.json \
  --text-output reports/report.txt
```

Expected results:

- The nested EICAR sample is detected as `infected`.
- The mock file containing suspicious API names is detected as `suspicious`.
- The clean sample remains clean.
