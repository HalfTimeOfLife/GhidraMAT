# GhidraMAT — Changelog

All notable changes to this project are documented in this file.

---

## v0.9

**New feature: GhidraMAT findings panel**

Added a dedicated Ghidra findings panel accessible from `Window` / `Analyze > GhidraMAT > Show Findings`.

- Displays findings in a sortable table with:
  - `Severity`
  - `Category`
  - `Name`
  - `Type`
  - `MITRE`
- Added filtering by severity, category, and detection type
- Findings can be sorted directly from the table
- Double-clicking a finding navigates to the associated address in Ghidra
- Added support for grouped xrefs and function context in the findings panel
- Added a dedicated `Show Findings` action to reopen the panel during the current Ghidra session

**New detection type: `section_names`**

Added PE section-name detection as a dedicated signature type.

This allows packer identification through characteristic PE section names without relying on generic strings or byte patterns.

- Added `get_section_names(context)` to retrieve section names from the analyzed program
- Added `section_names` to the signature schema
- Added `section_names` detection support in `utils/detection.py`
- Added `section_names` to report generation and findings display
- Section-name matches are represented as `Finding` objects with `type_of_technique="section_names"`

This is particularly useful for packer detection, where section names such as `UPX0`, `UPX1`, `.aspack`, `.adata`, `.MPRESS1`, `.MPRESS2`, and `petite` can provide strong static indicators.

****Signatures: `packer.json`****

Added packer detection signatures covering common Windows PE packers.

Tested packers:

- ASPack
  - `.aspack`
  - `.adata`
- MPRESS
  - `.MPRESS1`
  - `.MPRESS2`
- Petite
  - `petite`
  - `upx_unpack_stub_prologue`
- UPX
  - `UPX0`
  - `UPX1`
  - `upx_unpack_stub_prologue`

Packer detection combines `section_names` and `byte_patterns`, allowing detection to remain effective when one type of indicator is unavailable.

MITRE ATT&CK coverage:

- `T1027.002` - Software Packing

****Tested against****

Packed Windows PE binaries from the [Packing-Box packed PE dataset]([https://github.com/packing-box/dataset-packed-pe/tree/main/packed](https://github.com/packing-box/dataset-packed-pe/tree/main/packed)):

- `aspack_AccessEnum.exe` - ASPack
  - `.aspack`
  - `.adata`
- `mpress_AccessEnum.exe` - MPRESS
  - `.MPRESS1`
  - `.MPRESS2`
- `petite_calc.exe` - Petite
  - `petite`
  - `upx_unpack_stub_prologue`
- `upx_calc.exe` - UPX
  - `UPX0`
  - `UPX1`
  - `upx_unpack_stub_prologue`

---

## v0.8

**Refactoring: generalized config loading**

`load_scoring_config` in `core/scoring.py` replaced by a generic `load_config(path)`
in `utils/utils.py`, reusable for any JSON config file. `compute_risk_score` updated
accordingly. Tests added in `test_utils.py`.

**New feature: YARA rule generation**

GhidraMAT can now export findings as YARA rules.

- One rule per category, grouped in a single `.yar` file alongside the txt/JSON reports
- Eligible findings: non-combo_only, non-LOW, of type strings, byte_patterns, or string_patterns
- Condition threshold: 3 of them
- Rule naming: `GhidraMAT_<sample>_<category>`
- Controlled via `config/ghidramat_config.json` (`generate_yara: true/false`)
- Added `pattern` attribute to `Finding` for byte_patterns and string_patterns
- Tests added in `test_report.py`, `test_finding.py`, `test_detection.py`

**Bug fix / Change of structure - byte pattern scanner extended to data sections**

`scan_byte_pattern` previously only scanned executable sections via `getInstructions()`, missing cryptographic constants stored in `.rodata` and `.data` sections. The scanner now also iterates non-executable initialized memory blocks via `getByte()` to detect embedded lookup tables (AES S-box, ChaCha20 constants, etc.).

*Known limitation: data-section scanning reads memory byte by byte via `getByte()` to avoid the Java<->Python array bridge issue. Scanning large binaries with big data sections may be slow.*

**Signatures: `crypto.json`**

Detection of cryptographic primitives and custom encryption implementations.
MITRE ATT&CK coverage:
  - `T1027.013`
  - `T1140`
  - `T1573.001`
  - `T1573.002`

**Tested against**

Real-world malware from [MalwareBazaar](https://bazaar.abuse.ch/) and custom test binaries from [B-Con/crypto-algorithms](https://github.com/B-Con/crypto-algorithms) compiled with mingw-w64:

WannaCry (`ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa`):

- `T1573.001` - Encrypted Channel (Symmetric):
  - `CryptAcquireContextA`, `CryptEncrypt` resolved dynamically via `GetProcAddress`
- `T1140` - Deobfuscate/Decode Files or Information:
  - `CryptDecrypt` resolved dynamically via `GetProcAddress`

test_aes.exe - B-Con/crypto-algorithms (`a0ea502730abcc5df244bc98f4467bfeaea2843864d153f8a5a3b1bd0da748c3`):

- `T1027.013` - Encrypted/Encoded File:
  - `aes_sbox` detected in `.rodata` section
  - `aes_inv_sbox` detected in `.rodata` section

test_sha256.exe - B-Con/crypto-algorithms (`ac8f31878ea83109128f71467adaabb52b75767437d6688df55c6298cc407203`):

- No crypto findings - SHA-256 IV constants compiled as immediate values, not stored as a static table

*Note: the string detection layer is essential for crypto.json - without it, zero crypto detections on WannaCry. Crypto combinations were not triggered on any sample - APIs resolved dynamically are absent from the IAT.*

**YARA rules tested against**

al-khaser x64 (`0cd8a40f...`) - 3 rules generated: `anti_debug`, `anti_vm`, `injection`

---

## v0.7

**New detection type: `string_patterns`**

Added a fifth detection type alongside `imports`, `strings`, `byte_patterns`, and `combinations`.

`string_patterns` applies regular expression matching against Ghidra-defined strings, enabling detection of variable-length indicators such as URLs, IP addresses, and other patterns that cannot be covered efficiently by exact string matching.

- Added `"string_patterns": {}` section to signature files
- Updated `validate_signatures.py` schema:
  - `string_patterns` added to required top-level keys
  - regex patterns validated at load time and rejected when invalid
- Added detection support in `utils/detection.py`
  - One `Finding` generated per matching signature
  - Matched string values stored as xref labels
  - Grouping behavior aligned with `byte_patterns`
- Added `string_patterns` to report generation types
- Added unit tests covering the new detection path and signature validation

**Signatures: `network.json`**

Detection of network communication capabilities and C2-related indicators.
MITRE ATT&CK coverage:
  - `T1071.001`
  - `T1071.004`
  - `T1095`
  - `T1571`

**Tested against**

Real-world malware sample from [theZoo](https://github.com/ytisf/theZoo):

Kelihos (https://github.com/ytisf/theZoo/tree/master/malware/Binaries/Kelihos):

- SHA256:
  `89c2d370bfa36f1d4c3e4f2ff36f966bafef3e1179319e3a4a0f2a344896bc41` (`dumped.exe`)

Confirmed network behaviors via triggered combinations:

- `T1071.001` - Web Protocols:
  - `WinINet full HTTP with response`
- `T1071.004` - DNS:
  - `DnsQuery_A` capability detected
- `T1095` - Non-Application Layer Protocol:
  - Winsock bidirectional communication (`WSASocketA`, `WSASend`, `WSARecv`)

---

## v0.6

**Global risk scoring**

Aggregate all findings into a single risk level for the analyzed binary.

- Added `compute_risk_score(findings)` in new file `core/scoring.py`
- Global risk levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`
- Risk level computed from findings aggregation (e.g. at least one `CRITICAL` finding results in `CRITICAL`, multiple `HIGH` findings increase the overall risk level)
- Displayed at the top of the plaintext report and exported in JSON under `summary.risk_score`

**Configurable scoring thresholds**

Risk scoring thresholds can now be adjusted without modifying the source code.

- Added `config/scoring_config.json`
- Thresholds loaded dynamically at analysis time

**Signatures: `impair_defenses.json`**

Detection of defense impairment techniques targeting security controls and analysis mechanisms.

- MITRE ATT&CK coverage: `T1562.001`, `T1562.004`, `T1070.001`
- Detection of AV/EDR termination, Microsoft Defender registry tampering, security process termination, event log clearing, and firewall configuration manipulation
- AMSI patch detection via byte patterns

**Tested against**

Custom test binary compiled with mingw-w64 from C source
(`sample_test/test_impair_defenses.c`) exercising targeted technique APIs directly.

Confirmed detections:
- `T1562.001` — AV/EDR service termination (SCM): combination triggered
- `T1562.001` — Registry-based Defender tampering: combination + CRITICAL strings
- `T1562.001` — AV/EDR process termination: combination triggered
- `T1070.001` — Event log clearing: CRITICAL combination triggered
- `T1562.004` — Firewall command string: CRITICAL string triggered

*Known false positive*:
- `T1547.001` Registry Run Key persistence triggered by generic `RegCreateKeyExA` + `RegSetValueExA` usage regardless of the target registry key.

---


## v0.5

**Unit tests for the detection engine**

Extended test coverage to the core analysis pipeline using a full fake Ghidra
object hierarchy (`tests/fakes.py`) that enables pytest-based testing outside
the Ghidra runtime.

- `tests/fakes.py`: FakeAddress, FakeSymbol, FakeData, FakeFunction, FakeInstruction,
  FakeReference, and manager-level fakes (FakeSymbolTable, FakeListing, FakeRefManager,
  FakeFuncManager, FakeMemory, FakeProgram, FakeMonitor), assembled into FakeContext
- `tests/test_detection.py`: covers imports, strings, byte patterns, combinations,
  category propagation, empty signatures, and monitor interaction
- `tests/test_utils.py`: `load_signatures` version mismatch and missing file cases
- `tests/test_report.py`: JSON structure, TXT sections by category/severity/type

**Bug fix -- MITRE summary includes unconfirmed combo_only tags**

`build_header()` and `generate_json()` listed the MITRE tag of every finding in
a category's summary, including `combo_only` imports whose combination never
triggered. Both now filter `combo_only` findings out of the summary MITRE list.

**Signatures: `persistence.json`**

Detection of persistence mechanisms across MITRE `T1547` (.001, .002, .003, .004,
.005, .009, .014), `T1543.003`, `T1053.005`, `T1546` (.001, .003, .009, .010, .011,
.012, .015), and `T1197`.

- 28 imports, 43 strings, 0 byte patterns, 10 combinations
- `byte_patterns` intentionally empty across the board for this category

**Tested against**

Real-world malware from MalwareBazaar: PlugX (`3cdd33de...`), Berbew/Padodor
(3 samples), Hupigon (`465d3aac...`), Ramnit (`ee937854...`).

3 of 17 targeted sub-techniques confirmed via triggered combinations, cross-validated
across 4 independent families: `T1547.001` (Registry Run Key), `T1547.004` (Winlogon
Helper DLL), `T1543.003` (Windows Service, including the "existing service hijack"
variant, confirmed on Hupigon). Remaining sub-techniques (`T1546.003/.009/.010/.012/.015`,
`T1053.005`, `T1197`, `T1547.002/.003/.005/.009/.014`) were not observed in this sample
set.

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