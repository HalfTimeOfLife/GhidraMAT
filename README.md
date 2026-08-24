<div align="center">
  <img src="ghidramat_icon.png" width="128" height="128"/>
  
  # GhidraMAT -- Malware Analysis Toolkit for Ghidra
</div>

Ghidra script framework for automated static detection of malware behaviors: anti-debug, anti-VM, packing, C2 indicators, process injection, persistence and defense impairment.

[![CI](https://github.com/HalfTimeOfLife/GhidraMAT/actions/workflows/ci.yml/badge.svg)](https://github.com/HalfTimeOfLife/GhidraMAT/actions/workflows/ci.yml)

> **Platform support:** GhidraMAT currently targets **Windows PE binaries**. Linux ELF and macOS Mach-O support is planned for a future release.

---

## Detection Modules

The file `detection.py` provides the generic detection engine for all GhidraMAT categories: it loads category-specific signatures from [signatures/](signatures/) and identifies suspicious imports, strings, string patterns, byte patterns, and import combinations in the analyzed binary, returning them as Finding objects.

| Category | What it detects | Status |
|---|---|---|
| `anti_vm` | VM environment detection — `CPUID` hypervisor checks, firmware/SMBIOS table scanning, hardware fingerprinting, timing anomalies (`RDTSC`, sleep-skipping), user activity absence, VM-specific registry keys, device paths and process names | UP |
| `anti_debug` | `IsDebuggerPresent`, `NtQueryInformationProcess`, breakpoint scanning, SEH tricks | UP |
| `packer` | Known packer/protector artifacts (strings, byte patterns) - UPX, Themida, VMProtect and similar. | UP |
| `network` | C2 indicators, hardcoded IPs/URLs, non-standard ports, suspicious User-Agents, DNS-based C2, raw socket usage | UP |
| `crypto` | AES S-box constants, CryptoAPI/CNG usage chains, custom cipher constants (ChaCha20, Blowfish, TEA/XTEA) | UP |
| `injection` | Classic DLL injection, Process Hollowing, APC injection, Thread Hijacking, Process Doppelgänging, ListPlanting -- detected via dangerous API combinations | UP |
| `persistence` | Run registry keys, scheduled tasks, service installation, startup folder writes, WMI/COM/LSA event-triggered execution | UP |
| `impair_defenses` | Active defense neutralization — disabling Windows Defender, clearing event logs, patching AMSI, firewall tampering, security tool termination | UP |

> Section entropy analysis and PE header validation for `packer` are **not** part of the signature-driven engine -- see [ROADMAP.md](ROADMAP.md).

---

## Architecture of the project

Signatures are fully **decoupled from detection logic**. API names, byte patterns, string patterns and suspicious strings live in JSON files under [signatures/](signatures/).

```
GhidraMAT/
├── analyzer.py                 # Main runner
├── conftest.py                 # pytest path configuration
├── ruff.toml                   # Ruff linter configuration
├── config/
│   ├── ghidramat_config.json   # Runtime config (e.g. generate_yara)
│   └── scoring_config.json     # Risk scoring thresholds
├── core/
│   ├── context.py              # Wraps Ghidra program object
│   ├── finding.py              # Finding data model
│   ├── panel.py                # Ghidra Panel
│   ├── report.py               # Report generation (plaintext + JSON + YARA)
│   └── scoring.py              # Global risk score aggregation
├── scripts/
│   └── validate_signatures.py  # Signature schema validator (used by pre-commit)
├── signatures/                 # Declarative JSON signatures grouped by category
│   ├── README.md
│   ├── anti_debug.json
│   ├── anti_vm.json
│   ├── crypto.json
│   ├── impair_defenses.json
│   ├── injection.json
│   ├── network.json
│   ├── packer.json
│   └── persistence.json
├── tests/
│   ├── fakes.py                 # Fake Ghidra object hierarchy for pytest
│   ├── test_detection.py
│   ├── test_finding.py
│   ├── test_report.py
│   ├── test_scoring.py
│   ├── test_utils.py
│   └── test_validate_signatures.py
└── utils/
    ├── detection.py            # Detection engine
    ├── pattern.py              # Byte pattern scanner
    ├── utils.py                # Shared helpers (imports, strings, signatures loading)
    └── xrefs.py                # Cross-reference resolution
```

---

## Signatures

Each category has a dedicated JSON file under [signatures/](signatures/). A signature file contains five detection types: `imports`, `strings`, `section_names`, `byte_patterns`, `string_patterns`, and `combinations`. See [signatures/README.md](signatures/README.md) for the full format specification.

Every signature file carries a `sig_version` field. At load time, `load_signatures()` checks that `sig_version` matches the `SIGNATURES_VERSION` constant defined in `utils/utils.py`. A mismatch raises a `ValueError` and aborts the analysis for that category. This guarantees that the running code and the signature files are always in sync.

```json
{
    "sig_version": 1,
    "imports": {},
    "strings": {},
    "section_names": {},
    "byte_patterns": {},
    "string_patterns": {},
    "combinations": []
}
```

To validate all signature files against the schema without running Ghidra, use the standalone validator:

```bash
python scripts/validate_signatures.py
```

The validator is also registered as a pre-commit hook and runs automatically on every `git commit` that touches a `.json` file under [signatures/](signatures/).

---
## Ghidra findings panel

Before report generation, GhidraMAT opens an interactive findings panel displaying all findings detected during the analysis.

The panel provides a centralized view of the detected behaviors and allows the analyst to quickly inspect and navigate between findings without having to rely exclusively on the generated reports.

### Findings table

Each finding is displayed with the following information:

| Column     | Description                                                                    |
| ---------- | ------------------------------------------------------------------------------ |
| `Severity` | Severity assigned to the finding (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`)      |
| `Category` | Detection category, such as `anti_vm`, `anti_debug`, `injection`, or `network` |
| `Name`     | Name of the detected signature or behavior                                     |
| `Type`     | Detection type, such as an import, string, byte pattern, or combination        |
| `MITRE`    | Associated MITRE ATT&CK technique, when available                              |

Findings can be sorted directly from the table to help prioritize the most relevant results.

### Filtering

The panel provides filtering capabilities to narrow down the displayed findings.

Findings can be filtered by:

- Severity
- Category
- Detection type
- Mitre

For example, this makes it possible to display only `HIGH` findings and focus exclusively on `anti_vm` detections.

### Navigation

Findings associated with a Ghidra address can be opened directly from the panel.

Double-clicking a finding navigates to the corresponding location in the current Ghidra program, allowing the analyst to inspect the surrounding code, references, and other contextual information.

### Re-opening the panel

After the panel has been created by running GhidraMAT, it can be re-opened during the same Ghidra session without running the analysis again.

The panel can be accessed through:

**Window → GhidraMAT → Show Findings**

---



## Report generation

After analysis, GhidraMAT writes report files to the [reports/](reports/) directory (created automatically if absent):

| Format | Filename | Contents |
|---|---|---|
| Plaintext | `report_<name>_<timestamp>.txt` | Human-readable findings grouped by category, type, and severity, including the global risk score |
| JSON | `report_<name>_<timestamp>.json` | Machine-readable findings with full metadata, suitable for pipeline integration |
| YARA | `rules_<name>_<timestamp>.yar` | One YARA rule per category, generated when `generate_yara: true` in `config/ghidramat_config.json` |

All files share the same timestamp, so they can always be matched to the same analysis run. The JSON report includes tool version, signature version, program hashes, a global risk score, and a summary broken down by severity and category.

The [reports/](reports/) directory is excluded from version control via [.gitignore](.gitignore).



---

## Requirements

- Ghidra 10.x or later
- PyGhidra: See [Installation guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)
- `pre-commit`, `ruff`, and `pytest` — `pip install pre-commit ruff pytest && pre-commit install`

---

## Running tests

```bash
pytest
```

--- 

## Getting Started

1. Open your target binary in **Ghidra**
2. Run **Auto Analysis**
3. Go to **Window → Script Manager**
4. Add the `GhidraMAT/` folder to your script directories :
    1. In Ghidra, open `Window` → `Script Manager`
    2. Click the three-bar menu (top right) → `Manage Script Directories`
    3. Click the green **+** button → navigate to the `GhidraMAT/` folder → OK

You can then launch **GhidraMAT** using one of the following methods:

### Option 1: Script Manager

Run the main script in the script manager of Ghidra:

`analyzer.py`

### Option 2: Analysis Menu (Recommended)

Once the scripts directory is added, the analyzer is also available directly from:

`Analysis → GhidraMAT`

### Option 3: Toolbar

The analyzer can be launched using the toolbar icon: ![GhidraMAT](ghidramat_icon_small.png)

### Option 4: Key Binding

By default, the analyzer can be launched using the key binding `Ctrl+Shift+A`.

---

## Project status

See [ROADMAP.md](ROADMAP.md) for the planned release schedule and [CHANGELOG.md](CHANGELOG.md) for the history of changes.