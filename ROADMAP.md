# GhidraMAT — Roadmap

This document describes the planned release schedule for GhidraMAT. Each version ships one feature and one signature file.

Current version: **v0.3**

---

## v0.4 — CI GitHub Actions + `injection.json`

**Feature: CI GitHub Actions**

Automate quality checks server-side, independently of local pre-commit setup.

- `.github/workflows/ci.yml` running `ruff`, `pytest`, and `validate_signatures.py` on every push and PR
- CI status badge in [README.md](Readme.md)

**Signatures: `injection.json`**

Detection of process injection techniques — MITRE `T1055`.

---

## v0.5 — Unit tests + `persistence.json`

**Feature: Unit tests for the detection engine**

Extend test coverage beyond `Finding` and `validate_signatures` to the core analysis pipeline.

- `detection.py`: mock Ghidra `Context`, verify the 4 matching types (imports, strings, byte patterns, combinations) produce correct `Finding` objects
- `report.py`: verify JSON structure (`meta`, `summary`, `findings`), verify TXT sections are present by category and severity
- `load_signatures`: version mismatch raises `ValueError`, missing file raises `FileNotFoundError`

**Signatures: `persistence.json`**

Detection of persistence mechanisms — MITRE `T1547`.

---

## v0.6 — Global risk scoring + `impair_defenses.json`

**Feature: Global risk score**

Aggregate all findings into a single risk level for the analyzed binary.

- `compute_risk_score(findings)` in new file `core/scoring.py`
- Global level: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `CLEAN` based on findings aggregation (e.g. ≥1 CRITICAL → CRITICAL, ≥3 HIGH → HIGH, etc.)
- Displayed at the top of the TXT report and in the JSON output under `summary.risk_score`

**Signatures: `impair_defenses.json`**

Detection of defense impairment techniques — MITRE `T1562`.

---

## v0.7 — Pattern scanner improvements + `network.json`

**Feature: Improved pattern scanner**

Extend the byte pattern scanner with better coverage and flexibility:

- Multi-byte wildcard support in patterns (e.g. `0F ?? ?? A2` to skip N consecutive bytes)
- Update related unit tests

**Signatures: `network.json`**

Detection of C2 communication and network indicators — MITRE `T1071`.

---

## v0.8 — Cross-category detections + `crypto.json`

**Feature: Cross-category detection**

Allow a single signature to surface findings across multiple categories simultaneously.

- Optional `also_in` field in signature JSON: `"also_in": ["impair_defenses"]`
- The engine duplicates the finding in secondary categories with a note `(cross-ref from X)`
- Update `validate_signatures.py`, tests, and report output accordingly

**Signatures: `crypto.json`**

Detection of cryptographic primitives and custom encryption — MITRE `T1027`.

---

## v0.9 — Ghidra results panel + `packer.json`

**Feature: Dedicated Ghidra results panel**

Display findings directly inside Ghidra instead of only in the console and report files.

- Dedicated Ghidra component (`ComponentProvider`, `GTable`) showing a findings table
- Columns: Severity, Category, Name, Type, MITRE
- Sortable columns, filters by severity and category
- Double-click on a finding navigates to the corresponding address in the Ghidra listing

**Signatures: `packer.json`**

Detection of packed or protected binaries — MITRE `T1027`.

---

## v1.0 — Full documentation and signatures review (Runtime-constructed string detection *(optional — delivered if feasible)*)

**Feature: Runtime-constructed string detection** *(optional — delivered if feasible)*

Add detection of strings that are never stored as literals in the binary but are built
character by character at runtime (e.g. assigning individual characters into a buffer:
`buf[0] = 'A'; buf[1] = 'B'; ...`). These strings are invisible to standard string
extraction and require dataflow or pattern-based reconstruction to surface them.

**Feature: Complete documentation**

- Updated README with Ghidra panel screenshots and annotated TXT/JSON report examples
- `CHANGELOG.md` covering all versions from v0.1
- `CONTRIBUTING.md`: how to add a signature, naming conventions, how to run tests
- Enriched Getting Started with a full walkthrough on a public sample (MalwareBazaar)

**Signatures: full review**

- Validation of all signatures against real public samples (MalwareBazaar, VirusTotal)
- Remove or reclassify false positives identified during testing
- Severity consistency check across all 8 signature files

---

## v1.0+ — Ongoing maintenance

GhidraMAT will continue to evolve after v1.0. New signatures will be added as new evasion techniques, packers, or malware behaviors are discovered or documented. New features may also be introduced if relevant improvements are identified.

**Linux and macOS coverage**

Extend all signature files with platform-specific techniques for Linux ELF and macOS  binaries. Only techniques that are genuinely relevant to each platform will be added.

---

## Summary

| Version | Feature | Signatures |
|---|---|---|
| v0.4 | CI GitHub Actions | `injection.json` |
| v0.5 | Unit tests for detection engine | `persistence.json` |
| v0.6 | Global risk scoring | `impair_defenses.json` |
| v0.7 | Pattern scanner improvements | `network.json` |
| v0.8 | Cross-category detections | `crypto.json` |
| v0.9 | Ghidra results panel | `packer.json` |
| v1.0 | Runtime string detection + full documentation | Signatures review |
| v1.0+ | N/A | Signatures enrichment |