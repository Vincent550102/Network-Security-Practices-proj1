# Project I Speaker Notes - 10 Minutes

## 0:00-0:45 - Opening

Introduce Project I as a functional signature-based virus scanner named Sentinel. Emphasize that the goal is not to create malware, but to safely detect a mock malware sample using known signatures.

## 0:45-2:00 - System Function Overview

Explain the main workflow: load signatures, traverse files, read bytes, calculate hashes, search patterns, run heuristic checks, and generate reports. Mention that all scanning is read-only.

## 2:00-3:15 - Architecture

Walk through the architecture diagram. Highlight that file traversal and scanning are separated from reporting. Explain why this makes the scanner easier to test and extend.

## 3:15-5:30 - Live Demo

Run:

```bash
python3 -m sentinel scan \
  --target samples \
  --signatures signatures.json \
  --output reports/report.json \
  --text-output reports/report.txt
```

Show:

- `samples/nested/deep/eicar.com`
- `samples/suspicious/api_notes.txt`
- `reports/report.txt`

Key talking point: the EICAR file is harmless and used only as a standard antivirus test string.

## 5:30-7:15 - Demo Result Explanation

Explain the output counts:

- 3 scanned files
- 1 clean file
- 1 infected file
- 1 suspicious file
- 0 errors

For the infected file, point out SHA256, MD5, and byte-pattern matches. For the suspicious file, explain heuristic score 8 and threshold 5.

## 7:15-8:45 - System Features

Emphasize:

- Hash map lookup for fast exact matching
- Chunk-based scanning for memory efficiency
- Carry-over bytes for cross-chunk pattern matching
- Explainable heuristic rules
- JSON/text reports for verification

## 8:45-9:30 - Testing

Mention that the system has 9 tests and all pass. Briefly list the most important test cases: EICAR detection, heuristic scoring, nested folders, empty folders, missing target, and large-file skip.

## 9:30-10:00 - Closing

Conclude that Sentinel satisfies Project I by implementing a safe, functional, and explainable virus scanner with reproducible demo output and a complete report.
