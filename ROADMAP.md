# GhidraMAT - Roadmap

This document describes the planned release schedule for GhidraMAT. Each version ships one core feature and one signature file. Secondary features are possible in each release if they don't affect the scope.

Current version: **v0.6**

---

## v0.7 - `string_patterns` detection type + `network.json`

**Feature: `string_patterns` detection type**

Add a fifth detection type alongside `imports`, `strings`, `byte_patterns`, and `combinations`. `string_patterns` applies regex matching against Ghidra's defined strings, enabling detection of hardcoded URLs, IP addresses, and other variable-length indicators that exact-string matching cannot cover.

- New `"string_patterns": {}` section in every signature file
- Schema update in `validate_signatures.py`: `string_patterns` added to required top-level keys, regex pattern validated at load time (must compile without error)
- Detection loop in `utils/detection.py`: one Finding per matching signature, matched values stored as xref labels (same grouping logic as `byte_patterns`)
- `"string_patterns"` added to `TYPES` in `core/report.py`
- Unit tests for the new detection path and the validator

**Signatures: `network.json`**

Detection of C2 communication and network indicators.

- MITRE ATT&CK coverage: `T1071.001` (Web Protocols), `T1071.004` (DNS), `T1095` (Non-Application Layer Protocol), `T1571` (Non-Standard Port)
- Import and combination coverage: WinINet (`InternetOpenA/W`, `InternetConnectA/W`, `HttpOpenRequestA/W`, `HttpSendRequestA/W`, `InternetReadFile`), WinHTTP (`WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`), Winsock (`WSAStartup`, `socket`, `connect`, `send`, `recv`, `bind`), DNS (`DnsQuery_A/W`, `getaddrinfo`), download helpers (`URLDownloadToFileA/W`, `DeleteUrlCacheEntryA/W`)
- `string_patterns` coverage: hardcoded HTTP/HTTPS URLs and non-private routable IP addresses

---

## v0.8 - Cross-category detections + `crypto.json`

**Feature: Cross-category detection**

Allow a single signature to surface findings across multiple categories simultaneously.

- Optional `also_in` field in signature JSON: `"also_in": ["impair_defenses"]`
- The engine duplicates the finding in secondary categories with a note `(cross-ref from X)`
- Update `validate_signatures.py`, tests, and report output accordingly

**Small addition: conditional dependency (`requires`)**

- `"requires": "network"` - a finding is only emitted if another category also matched
- Reduces false positives in ambiguous categories

**Secondary feature: Automatic YARA rule generation**

- `--generate-yara` option: produces a `.yar` file from findings' strings and byte patterns, only when the findings are meaningful signal (not just generic import lists)
- Includes MITRE metadata, grouped by category
- Gives a concrete, testable output for the v1.0 signature validation pass against public samples (MalwareBazaar/VT)

**Signatures: `crypto.json`**

Detection of cryptographic primitives and custom encryption (specific MITRE ATT&CK Technique IDs will be added during the development of this version).

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
| v0.7 | `string_patterns` detection type | - | `network.json` | Planned |
| v0.8 | Cross-category detections | `requires` field, YARA export | `crypto.json` | Planned |
| v0.9 | Ghidra results panel | - | `packer.json` | Planned |
| v1.0 | Documentation + signature review | Basic runtime string detection | - | Planned |
| v1.1 | Full runtime string detection | - | - | Deferred |
| v1.2 | Linux/macOS coverage | - | - | Deferred |
| v1.2+ | Ongoing maintenance | To be determined | - | Ongoing |