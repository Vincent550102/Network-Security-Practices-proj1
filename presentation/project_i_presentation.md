# Project I: Sentinel Virus Scanner

## Slide 1 - Title

**Sentinel: Signature-Based Virus Scanner**

- Network Security Practices - Project I
- Goal: scan a directory, detect known malware signatures, and produce a security report
- Demo target: safe EICAR test file hidden in nested folders

## Slide 2 - What The System Does

- Recursively scans files under a target directory
- Computes MD5 and SHA256 hashes for exact signature matching
- Searches file bytes for known hex patterns
- Applies heuristic rules for suspicious behavior indicators
- Outputs JSON and text reports

## Slide 3 - System Architecture

```text
Target Directory
      |
      v
File Traversal -> Chunk Reader -> Hash + Pattern + Heuristic Checks
      |                                      |
      v                                      v
Skipped/Error List                    Findings
      |                                      |
      +-----------------> JSON/Text Report <-+
```

## Slide 4 - Demo Setup

```text
samples/
  clean/readme.txt
  nested/deep/eicar.com
  suspicious/api_notes.txt
```

- `clean/readme.txt`: should remain clean
- `nested/deep/eicar.com`: safe mock virus test file
- `suspicious/api_notes.txt`: contains suspicious API names for heuristic scoring

## Slide 5 - Demo Command

```bash
python3 -m sentinel scan \
  --target samples \
  --signatures signatures.json \
  --output reports/report.json \
  --text-output reports/report.txt
```

- The scanner only reads files
- It never executes scanned files
- Reports are generated after the scan finishes

## Slide 6 - Demo Result

```text
Scanned files: 3
Clean files: 1
Infected files: 1
Suspicious files: 1
Skipped files: 0
Errors: 0
```

- EICAR sample matched by SHA256, MD5, and byte pattern
- Suspicious sample reached heuristic score 8
- Clean sample was not flagged

## Slide 7 - System Features

- Fast exact lookup with hash maps
- Chunk-based scanning to avoid loading large files into memory
- Cross-chunk pattern matching with carry-over bytes
- Explainable heuristic scoring
- Safe handling of symlinks, missing targets, and large files
- Structured report for verification

## Slide 8 - Testing And Verification

```bash
python3 -m unittest discover -s tests
```

- 9 tests currently pass
- Tests cover hash match, pattern match, heuristic scoring, nested folders, empty folders, missing targets, and large-file skipping
- Demo report is reproducible with the README command

## Slide 9 - Limitations And Future Work

- Does not unpack archives
- Does not emulate code execution
- Does not parse PE headers deeply
- Bloom Filter could be added for very large signature databases
- More signatures and richer heuristic rules could improve detection coverage

## Slide 10 - Closing

- Sentinel demonstrates the core workflow of signature-based malware detection
- It identifies known threats using hash and byte-pattern signatures
- It flags suspicious files using explainable heuristic scoring
- It produces reports that can be verified by TA or instructor
