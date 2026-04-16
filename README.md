# GhidraMAT -- Malware Analysis Toolkit for Ghidra

Ghidra script framework for automated static detection of malware behaviors: anti-debug, anti-VM, packing, C2 indicators, process injection, persistence and sandbox evasion.

---

## Detection Modules

In the directory [modules/](modules), there is all the file used for detecting suspicious behavior in the analyzed executable. This directory contains the following files :

| Module | What it detects | Status |
|---|---|---|
| `anti_vm.py` | `CPUID` VM checks, VMware/VirtualBox registry artifacts, VBOX/VMWARE strings, RDTSC delta | UP |
| `anti_debug.py` | `RDTSC`, `IsDebuggerPresent`, `NtQueryInformationProcess`, breakpoint scanning, SEH tricks | WIP |
| `packer.py` | Section entropy (Shannon > 7.2), malformed PE headers, abnormal section names, TLS callbacks, low import count | WIP |
| `network.py` | C2 indicators, hardcoded IPs/URLs, suspicious User-Agents, DGA-like strings, raw socket usage | WIP |
| `crypto.py` | AES S-box constants, RC4 key scheduling patterns, rolling XOR, custom magic constants | WIP |
| `injection.py` | Classic DLL injection, Process Hollowing, APC injection, Thread Hijacking -- detected via dangerous API combinations | WIP |
| `persistence.py` | Run registry keys, scheduled tasks, service installation, startup folder writes | WIP |
| `evasion.py` | Timing-based sandbox evasion, sleep acceleration, environment fingerprinting, uptime checks | WIP |

---

## Architecture of the project

Signatures are fully **decoupled from detection logic**. API names, byte patterns and suspicious strings live in JSON files under [signatures/](signatures).

```
GhidraMAT/
├── analyzer.py              # Main runner
├── core/
│   ├── context.py           # Wraps Ghidra program object
│   ├── finding.py           # Finding data model
│   └── report.py            # Report generation (plaintext)
├── modules/
│   └── anti_vm.py           # Anti-VM detection module
├── signatures/
│   └── signatures.json      # All signatures (imports, strings, byte_patterns, combinations)
└── utils/
    ├── utils.py             # Shared helpers (imports, strings, signatures loading)
    ├── xrefs.py             # Cross-reference resolution
    └── pattern.py           # Byte pattern scanner
```

---

## Report generation

GhidraMAT produces a structured report per binary with findings grouped by category, each annotated with its offset and matched signature. Reports are currently exported as plaintext. JSON export for pipeline integration is planned.

---

## Requirements

- Ghidra 10.x or later
- PyGhidra — [Installation guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md)

---

## Getting Started

1. Open your target binary in **Ghidra**
2. Run **Auto Analysis**
3. Go to **Window → Script Manager**
4. Add the `GhidraMAT/` folder to your script directories

You can then launch **GhidraMAT** using one of the following methods:

### Option 1 — Script Manager

Run the main script in the script manager of Ghidra:

`analyzer.py`

### Option 2 — Analysis Menu (Recommended)

Once the scripts directory is added, the analyzer is also available directly from:

`Analysis → GhidraMAT`

---