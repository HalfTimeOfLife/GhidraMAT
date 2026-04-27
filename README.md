<div align="center">
  <img src="ghidramat_icon.png" width="128" height="128"/>
  
  # GhidraMAT -- Malware Analysis Toolkit for Ghidra
</div>

Ghidra script framework for automated static detection of malware behaviors: anti-debug, anti-VM, packing, C2 indicators, process injection, persistence and sandbox evasion.

---

## Detection Modules

The file `detection.py` provides the generic detection engine for all GhidraMAT categories: it loads category-specific signatures from [signatures.json](signatures/signatures.json) and identifies suspicious imports, strings, byte patterns and import combinations in the analyzed binary, returning them as Finding objects. Here is the category supported :

| Category | What it detects | Status |
|---|---|---|
| `anti-vm` | `CPUID` VM checks, VMware/VirtualBox registry artifacts, VBOX/VMWARE strings, RDTSC delta | UP |
| `anti-debug` | `RDTSC`, `IsDebuggerPresent`, `NtQueryInformationProcess`, breakpoint scanning, SEH tricks | WIP |
| `packer` | Section entropy (Shannon > 7.2), malformed PE headers, abnormal section names, TLS callbacks, low import count | WIP |
| `network` | C2 indicators, hardcoded IPs/URLs, suspicious User-Agents, DGA-like strings, raw socket usage | WIP |
| `crypto` | AES S-box constants, RC4 key scheduling patterns, rolling XOR, custom magic constants | WIP |
| `injection` | Classic DLL injection, Process Hollowing, APC injection, Thread Hijacking -- detected via dangerous API combinations | WIP |
| `persistence` | Run registry keys, scheduled tasks, service installation, startup folder writes | WIP |
| `evasion` | Timing-based sandbox evasion, sleep acceleration, environment fingerprinting, uptime checks | WIP |

---

## Architecture of the project

Signatures are fully **decoupled from detection logic**. API names, byte patterns and suspicious strings live in JSON files under [signatures/](signatures/).

```
GhidraMAT/
├── analyzer.py              # Main runner
├── core/
│   ├── context.py           # Wraps Ghidra program object
│   ├── finding.py           # Finding data model
│   └── report.py            # Report generation (plaintext)
├── signatures               # Declarative JSON signatures grouped by family
│   ├── README.md
│   ├── anti_debug.json     
│   ├── anti_vm.json
│   ├── crypto.json
│   ├── evasion.json
│   ├── injection.json
│   ├── network.json
│   ├── packer.json
│   └── persistence.json
└── utils/
    ├── detection.py         # Detection module  
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

### Option 3 — Toolbar
The analyzer can be launched using the toolbar icon: ![GhidraMAT](ghidramat_icon_small.png)

### Option 4 — Key Binding
By default, the analyzer can be launched using the key binding `Ctrl+Shift+A`.

---
