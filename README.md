# Sentinel Virus Scanner

Sentinel is a functional signature-based virus scanner for the Network Security project. It scans files without executing them, compares file hashes and byte patterns against a JSON signature database, applies simple heuristic rules, and writes JSON/text reports.

## Features

- Recursive file and directory scanning.
- MD5 and SHA256 hash signature matching.
- Hex/string byte pattern matching with chunked reads.
- Heuristic scoring for suspicious strings such as process injection APIs.
- JSON report for structured output and text report for demos.
- Safe EICAR test sample in a nested folder structure.

## Project Layout

```text
sentinel/             Python package and CLI
signatures.json       Malware signature database
samples/              Demo files, including nested EICAR and suspicious mock file
tests/                Unit and integration-style tests
docs/project_report.md
reports/              Generated reports
```

## Run A Demo Scan

From the project root:

```bash
python3 -m sentinel scan \
  --target samples \
  --signatures signatures.json \
  --output reports/report.json \
  --text-output reports/report.txt
```

Expected result:

- `samples/nested/deep/eicar.com` is reported as `infected`.
- `samples/suspicious/api_notes.txt` is reported as `suspicious`.
- `samples/clean/readme.txt` remains clean.

## Run Tests

```bash
python3 -m unittest discover -s tests
```

## CLI Reference

```bash
python3 -m sentinel scan \
  --target <file-or-directory> \
  --signatures <signatures.json> \
  --output <report.json> \
  [--text-output <report.txt>] \
  [--max-file-size-mb 100] \
  [--chunk-size-kb 1024]
```

The scanner skips symlinks and files larger than `--max-file-size-mb`. It reads files in chunks and never executes scanned files.

## Signature Database Format

```json
{
  "hashes": {
    "sha256": {
      "hex_digest": {
        "name": "Threat name",
        "threat_level": "high"
      }
    },
    "md5": {}
  },
  "patterns": [
    {
      "name": "Pattern name",
      "hex": "deadbeef",
      "threat_level": "medium"
    }
  ],
  "heuristics": {
    "threshold": 5,
    "rules": [
      {
        "name": "Suspicious API",
        "string": "CreateRemoteThread",
        "score": 3,
        "threat_level": "high"
      }
    ]
  }
}
```

Hash signatures are stored in dictionaries, so exact hash lookup is constant time on average. Pattern and heuristic signatures are searched against file bytes while streaming chunks from disk.
