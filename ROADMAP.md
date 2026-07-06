# GhidraMAT — Roadmap

This document describes the planned release schedule for GhidraMAT. Each version ships one core feature and one signature file. Secondary features are possible in each release if they don't affect the scope.

Current version: **v0.4**

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

**Secondary feature: configurable scoring thresholds**

- `config/scoring_config.json` — thresholds adjustable without touching code

**Signatures: `impair_defenses.json`**

Detection of defense impairment techniques — MITRE `T1562`.

---

## v0.7 — Pattern scanner improvements + `network.json`

**Feature: Improved pattern scanner**

Extend the byte pattern scanner with better coverage and flexibility:

- Multi-byte wildcard support in patterns (e.g. `0F ?? ?? A2` to skip N consecutive bytes)
- Section-aware anchoring: patterns can specify `"section": ".text"` or `"anchor": {"section": "...", "alignment": 16}`
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

**Small addition: conditional dependency (`requires`)**

- `"requires": "network"` — a finding is only emitted if another category also matched
- Reduces false positives in ambiguous categories

**Secondary feature: Automatic YARA rule generation**

- `--generate-yara` option: produces a `.yar` file from findings' strings and byte patterns, only when the findings are meaningful signal (not just generic import lists)
- Includes MITRE metadata, grouped by category
- Gives a concrete, testable output for the v1.0 signature validation pass against public samples (MalwareBazaar/VT)

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

> **Scope note:** The plan is the Ghidra panel. If the rendered output isn't readable/usable enough once built, a standalone HTML version could be considered in a future release.

**Signatures: `packer.json`**

Detection of packed or protected binaries — MITRE `T1027`.

---

## v1.0 — Full documentation, signature review, and basic runtime string detection

**Feature: Complete documentation**

- Updated README with Ghidra panel screenshots and annotated TXT/JSON report examples
- `CHANGELOG.md` covering all versions from v0.1
- `CONTRIBUTING.md`: how to add a signature, naming conventions, how to run tests
- Enriched Getting Started with a full walkthrough on a public sample (MalwareBazaar)

**Feature: Runtime-constructed string detection (basic)** *(delivered if feasible)*

- Pattern matching on sequences of immediate assignments (`MOV [mem], 0x41`)
- No full dataflow analysis — just detection of simple char-by-char constructed strings
- Tested against 5 known public samples

**Signatures: full review**

- Validation of all signatures against real public samples (MalwareBazaar, VirusTotal), including the YARA rules generated in v0.8
- Remove or reclassify false positives identified during testing
- Severity consistency check across all 8 signature files

---

## v1.1 — Runtime string detection (full)

**Feature: Full runtime-constructed string detection**

- Dataflow analysis to reconstruct strings built through intermediate operations (XOR, ADD, etc.)
- Support for loop-based construction (e.g. `for i in range(len(key)): buf[i] = key[i] ^ 0x13`)
- Dataflow path visualization in the report

## v1.2 — Platform coverage

**Feature: Linux and macOS coverage**

- Extend signature files with platform-specific techniques for ELF and Mach-O
- Only techniques genuinely relevant to each platform are added
- `anti_vm` adapted for paravirt/`hypervisor.framework`, `persistence` adapted for cron/launchd, etc.

## v1.2+ — Ongoing maintenance

GhidraMAT will continue to evolve after v1.2. New signatures will be added as new evasion
techniques, packers, or malware behaviors are discovered or documented. Additional features may
be added if a genuine need is identified.

---

## Summary

| Version | Core feature | Small additions | Signatures | Status |
|---|---|---|---|---|
| v0.5 | Unit tests for detection engine | N/A | `persistence.json` | Planned |
| v0.6 | Global risk scoring | Configurable thresholds | `impair_defenses.json` | Planned |
| v0.7 | Pattern scanner improvements | Section-aware anchoring | `network.json` | Planned |
| v0.8 | Cross-category detections | `requires` field, YARA export | `crypto.json` | Planned |
| v0.9 | Ghidra results panel | — | `packer.json` | Planned |
| v1.0 | Documentation + signature review | Basic runtime string detection | — | Planned |
| v1.1 | Full runtime string detection | — | — | Deferred |
| v1.2 | Linux/macOS coverage | — | — | Deferred |
| v1.2+ | Ongoing maintenance | To be determined | — | Ongoing |