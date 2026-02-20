# GhidraMAT — Malware Analysis Toolkit for Ghidra

Ghidra script framework for automated static detection of malware behaviors: anti-debug, anti-VM, packing, C2 indicators, process injection, persistence and sandbox evasion.

---

## Detection Modules

In the directory [modules/](modules), there is all the file used for detecting suspicious behavior in the analyzed executable. This directory contains the following files :

| Module | What it detects |
|---|---|
| `anti_debug.py` | `RDTSC`, `IsDebuggerPresent`, `NtQueryInformationProcess`, breakpoint scanning, SEH tricks |
| `anti_vm.py` | `CPUID` VM checks, VMware/VirtualBox registry artifacts, VBOX/VMWARE strings, RDTSC delta |
| `packer.py` | Section entropy (Shannon > 7.2), malformed PE headers, abnormal section names, TLS callbacks, low import count |
| `network.py` | C2 indicators, hardcoded IPs/URLs, suspicious User-Agents, DGA-like strings, raw socket usage |
| `crypto.py` | AES S-box constants, RC4 key scheduling patterns, rolling XOR, custom magic constants |
| `injection.py` | Classic DLL injection, Process Hollowing, APC injection, Thread Hijacking — detected via dangerous API combinations |
| `persistence.py` | Run registry keys, scheduled tasks, service installation, startup folder writes |
| `evasion.py` | Timing-based sandbox evasion, sleep acceleration, environment fingerprinting, uptime checks |

---

## Architecture of the project

Signatures are fully **decoupled from detection logic**. API names, byte patterns and suspicious strings live in JSON files under [signatures/](signatures).

```
GhidraMAT/
├── analyzer.py              # Main runner
├── core/                    # Contains after detection behavior
├── modules/                 # One detection module per category
└── signatures/              # api_signatures.json, byte_patterns.json, strings.json
```

---

## Report generation

GhidraMAT produces a structured report per binary with findings grouped by category, each annotated with its offset and matched signature. Reports are exported as both JSON (for pipeline integration) and plaintext (for human review).

---

## Getting Started

1. Open your target binary in Ghidra and run auto-analysis
2. Go to **Window > Script Manager**
3. Add the `GhidraMAT/` folder to your script directories
4. Run `analyzer.py`

Requires Ghidra 10.x or later. No external dependencies.

---
