# GhidraMAT - Roadmap

This document describes the planned release schedule for GhidraMAT. Each version ships one core feature and one signature file. Secondary features are possible in each release if they don't affect the scope.

Current version: **v0.8**

---

## v0.9 - Ghidra results panel + `packer.json`

**Feature: Dedicated Ghidra results panel**

Display findings directly inside Ghidra instead of only in the console and report files.

- Dedicated Ghidra component (`ComponentProvider`, `GTable`) showing a findings table
- Columns: Severity, Category, Name, Type, MITRE
- Sortable columns, filters by severity and category
- Double-click on a finding navigates to the corresponding address in the Ghidra listing

> **Scope note:** The plan is the Ghidra panel. If the rendered output isn't readable/usable enough once built, a standalone HTML version could be considered in a future release.

**Signatures: `packer.json`**

Detection of packed or protected binaries (specific MITRE ATT&CK Technique IDs will be added during the development of this version).

---

## v1.0 - Full documentation, signature review, and basic runtime string detection

**Feature: Complete documentation**

- Updated README with Ghidra panel screenshots and annotated TXT/JSON report examples
- `CHANGELOG.md` covering all versions from v0.1
- `CONTRIBUTING.md`: how to add a signature, naming conventions, how to run tests
- Enriched Getting Started with a full walkthrough on a public sample (MalwareBazaar)

**Feature: Runtime-constructed string detection (basic)** *(delivered if feasible)*

- Pattern matching on sequences of immediate assignments (`MOV [mem], 0x41`)
- No full dataflow analysis - just detection of simple char-by-char constructed strings
- Tested against 5 known public samples

**Signatures: full review**

- Validation of all signatures against real public samples (MalwareBazaar, VirusTotal), including the YARA rules generated in v0.8
- Remove or reclassify false positives identified during testing
- Severity consistency check across all 8 signature files

---

## v1.1 - Runtime string detection (full)

**Feature: Full runtime-constructed string detection**

- Dataflow analysis to reconstruct strings built through intermediate operations (XOR, ADD, etc.)
- Support for loop-based construction (e.g. `for i in range(len(key)): buf[i] = key[i] ^ 0x13`)
- Dataflow path visualization in the report

## v1.2 - Platform coverage

**Feature: Linux and macOS coverage**

- Extend signature files with platform-specific techniques for ELF and Mach-O
- Only techniques genuinely relevant to each platform are added
- `anti_vm` adapted for paravirt/`hypervisor.framework`, `persistence` adapted for cron/launchd, etc.

## v1.2+ - Ongoing maintenance

GhidraMAT will continue to evolve after v1.2. New signatures will be added as new evasion
techniques, packers, or malware behaviors are discovered or documented. Additional features may
be added if a genuine need is identified.

---

## Summary

| Version | Core feature | Small additions | Signatures | Status |
|---|---|---|---|---|
| v0.9 | Ghidra results panel | - | `packer.json` | Planned |
| v1.0 | Documentation + signature review | Basic runtime string detection | - | Planned |
| v1.1 | Full runtime string detection | - | - | Deferred |
| v1.2 | Linux/macOS coverage | - | - | Deferred |
| v1.2+ | Ongoing maintenance | To be determined | - | Ongoing |