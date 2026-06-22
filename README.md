<div align="center">
  <img src="ghidramat_icon.png" width="128" height="128"/>
  
  # GhidraMAT -- Malware Analysis Toolkit for Ghidra
</div>

Ghidra script framework for automated static detection of malware behaviors: anti-debug, anti-VM, packing, C2 indicators, process injection, persistence and defense impairment.

[![CI](https://github.com/HalfTimeOfLife/GhidraMAT/actions/workflows/ci.yml/badge.svg)](https://github.com/HalfTimeOfLife/GhidraMAT/actions/workflows/ci.yml)

> **Platform support:** GhidraMAT currently targets **Windows PE binaries**. Linux ELF and macOS Mach-O support is planned for a future release.

---

## Detection Modules

The file `detection.py` provides the generic detection engine for all GhidraMAT categories: it loads category-specific signatures from [signatures/](signatures/) and identifies suspicious imports, strings, byte patterns and import combinations in the analyzed binary, returning them as Finding objects.

| Category | What it detects | Status |
|---|---|---|
| `anti_vm` | VM environment detection — `CPUID` hypervisor checks, firmware/SMBIOS table scanning, hardware fingerprinting, timing anomalies (`RDTSC`, sleep-skipping), user activity absence, VM-specific registry keys, device paths and process names | UP |
| `anti_debug` | `IsDebuggerPresent`, `NtQueryInformationProcess`, breakpoint scanning, SEH tricks | UP |
| `packer` | Section entropy (Shannon > 7.2), malformed PE headers, abnormal section names, TLS callbacks, low import count | WIP |
| `network` | C2 indicators, hardcoded IPs/URLs, suspicious User-Agents, DGA-like strings, raw socket usage | WIP |
| `crypto` | AES S-box constants, RC4 key scheduling patterns, rolling XOR, custom magic constants | WIP |
| `injection` | Classic DLL injection, Process Hollowing, APC injection, Thread Hijacking -- detected via dangerous API combinations | UP |
| `persistence` | Run registry keys, scheduled tasks, service installation, startup folder writes | WIP |
| `impair_defenses` | Active defense neutralization — disabling Windows Defender, clearing event logs, patching AMSI, firewall tampering, security tool termination | WIP |

> Categories marked WIP have empty signature files and produce no findings.
> The detection engine runs normally for all categories.

---

## Architecture of the project

Signatures are fully **decoupled from detection logic**. API names, byte patterns and suspicious strings live in JSON files under [signatures/](signatures/).

```
GhidraMAT/
├── analyzer.py                 # Main runner
├── conftest.py                 # pytest path configuration
├── ruff.toml                   # Ruff linter configuration
├── core/
│   ├── context.py              # Wraps Ghidra program object
│   ├── finding.py              # Finding data model
│   └── report.py               # Report generation (plaintext + JSON)
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
│   ├── test_finding.py
│   └── test_validate_signatures.py
└── utils/
    ├── detection.py            # Detection engine
    ├── pattern.py              # Byte pattern scanner
    ├── utils.py                # Shared helpers (imports, strings, signatures loading)
    └── xrefs.py                # Cross-reference resolution
```

---

## Signatures

Each category has a dedicated JSON file under `signatures/`. A signature file contains four detection types: `imports`, `strings`, `byte_patterns`, and `combinations`. See [signatures/README.md](signatures/README.md) for the full format specification.

Every signature file carries a `sig_version` field. At load time, `load_signatures()` checks that `sig_version` matches the `SIGNATURES_VERSION` constant defined in `utils/utils.py`. A mismatch raises a `ValueError` and aborts the analysis for that category. This guarantees that the running code and the signature files are always in sync.

```json
{
    "sig_version": 1,
    "imports": {},
    "strings": {},
    "byte_patterns": {},
    "combinations": []
}
```

To validate all signature files against the schema without running Ghidra, use the standalone validator:

```bash
python scripts/validate_signatures.py
```

The validator is also registered as a pre-commit hook and runs automatically on every `git commit` that touches a `.json` file under `signatures/`.

---

## Report generation

After analysis, GhidraMAT writes two report files to the `reports/` directory (created automatically if absent):

| Format | Filename | Contents |
|---|---|---|
| Plaintext | `report_<name>_<timestamp>.txt` | Human-readable findings grouped by category, type, and severity |
| JSON | `report_<name>_<timestamp>.json` | Machine-readable findings with full metadata, suitable for pipeline integration |

Both files share the same timestamp, so they can always be matched to the same analysis run. The JSON report includes tool version, signature version, program hashes, and a summary broken down by severity and category.

The `reports/` directory is excluded from version control via `.gitignore`.

---

## Requirements

- Ghidra 10.x or later
- PyGhidra — [Installation guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)
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

### Option 1 — Script Manager

Run the main script in the script manager of Ghidra:

`analyzer.py`

### Option 2 — Analysis Menu (Recommended)

Once the scripts directory is added, the analyzer is also available directly from:

`Analysis → GhidraMAT`

### Option 3 — Toolbar

The analyzer can be launched using the toolbar icon: ![GhidraMAT](ghidramat_icon_small.png)

### Option 4 — Key Binding

By default, the analyzer can be launched using the key binding `Ctrl+Shift+A`.

---

## Project status

See [ROADMAP.md](ROADMAP.md) for the planned release schedule and [CHANGELOG.md](CHANGELOG.md) for the history of changes.