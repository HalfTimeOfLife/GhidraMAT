# GhidraMAT — Changelog

All notable changes to this project are documented in this file.

---

## v0.4

**CI GitHub Actions**

Automated quality checks now run server-side on every push and pull request,
independently of the local pre-commit setup.

- `.github/workflows/ci.yml` runs `ruff`, `pytest`, and `validate_signatures.py`
- CI status badge added to `README.md`

**Signatures: `injection.json` (MITRE `T1055`)**

Detection of process injection techniques. Covers classic DLL injection, Process
Hollowing, APC injection (Early Bird and native), thread hijacking, section-based
injection, ListPlanting, and PE injection.

- 42 imports, 29 strings, 5 byte patterns, 19 combinations
- String-based detection layer for native ntdll APIs resolved via `GetProcAddress`
  at runtime (`NtCreateSection`, `NtMapViewOfSection`, `NtQueueApcThread`,
  `RtlCreateUserThread`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, and others) -- these APIs never appear in the IAT when dynamically resolved
- Byte patterns: PE magic header (`MZ`), `CREATE_SUSPENDED` flag, `NtUnmapViewOfSection`
  call sequence, module stomping marker
- MITRE sub-technique coverage: `T1055.001`, `T1055.002`, `T1055.003`, `T1055.004`,
  `T1055.012`, `T1055.013`, `T1055.015`

**Tested against**

redcanaryco/atomic-red-team:
`CreateProcess.exe` (Process Hollowing), `EarlyBird.exe` (APC Early Bird),
`NtQueueApcThreadEx.exe` (native APC), `RtlCreateUserThread.exe` (native remote thread),
`listPlanting.exe` (ListPlanting), `InjectView.exe` (section-based), `RedInjection.exe`
(PE injection)

---

## v0.3

**Anti-debug detection module (`anti_debug` — MITRE `T1622`)**

The `anti_debug` category is now fully operational. Covers debug flags (PEB, NtGlobalFlag,
KUSER_SHARED_DATA), object handle tricks, exception-based checks, timing attacks,
assembly-level patterns (INT3, INT2D, ICE, POPF), process memory inspection, and
interactive techniques (thread hiding, window enumeration, self-debugging anti-attach,
NTAPI patching). Signatures cross-referenced against [Check Point Anti-Debug Encyclopedia](https://anti-debug.checkpoint.com), [al-khaser](https://github.com/ayoubfaouzi/al-khaser), and [Unprotect Project](https://unprotect.it).

**Bug fix -- byte pattern scanner**

`scan_byte_pattern` was silently returning empty results on all binaries due to a Java <->
Python bytearray issue in PyGhidra. The scanner now iterates decoded instructions via
`getListing()` and reads bytes per instruction.

**Tests**

Added `pytest` test suite covering `Finding` serialization and `validate_signatures.py`
schema validation.

**Tested against**

al-khaser x64 (`0cd8a40f...`) -- 119 findings across `anti_vm` and `anti_debug`.

---

## v0.2

**JSON export**

Analysis results are now exported as a structured `.json` report in addition to the
existing plaintext `.txt` report. Both files share the same timestamp.

**Signature versioning**

Added `sig_version` field to all signature files. `load_signatures()` verifies the version
at load time and raises `ValueError` on mismatch, ensuring the running code and signature
files are always in sync.

**Improved xref display**

Cross-references are now deduplicated by function name with a call count (e.g. `main (3x)`),
capped at 6 distinct functions per finding.

**Bug fixes**

- `apply_visual_marking` and `create_bookmark` now skip external addresses.
- Byte pattern scanner rewritten to use a single `getBytes()` call instead of per-byte reads.

**Documentation**

Updated README.

---

## v0.1

Initial release.

**Anti-VM detection module (`anti_vm` -- MITRE `T1497`)**

First operational detection category. Signatures covering CPUID hypervisor checks,
RDTSC timing, firmware table scanning (SMBIOS/ACPI), registry artifact paths, VM-specific
device paths, process enumeration, hardware fingerprinting, and sleep-skipping sandbox
detection.

**Report generation**

Timestamped plaintext report with findings grouped by category, type, and severity.
Each finding includes MITRE ATT&CK mapping, description, and cross-references.

**Ghidra integration**

Visual markings and bookmarks applied by severity level directly in the Ghidra listing.

**Signature validation**

Pre-commit hook running `validate_signatures.py` on every commit touching a `.json` file
under `signatures/`.