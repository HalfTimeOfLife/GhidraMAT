# Signatures Format

GhidraMAT's detection logic is fully driven by the JSON files in this directory. This document explains the structure and available fields.

---

## File Structure

Signatures are split into **one file per category**. Each file is named after its category and contains four detection types:

```
signatures/
├── anti_vm.json
├── anti_debug.json
├── packer.json
├── network.json
├── crypto.json
├── injection.json
├── persistence.json
└── impair_defenses.json
```

Each file follows this structure:

```json
{
    "sig_version": 1,
    "imports": {},
    "strings": {},
    "byte_patterns": {},
    "combinations": []
}
```

The `sig_version` field is required. At load time, `load_signatures()` checks that it matches the `SIGNATURES_VERSION` constant in `utils/utils.py` and raises a `ValueError` on mismatch.

| Category | Description | MITRE Technique |
|---|---|---|
| `anti_vm` | Techniques used to detect virtualized or sandboxed environments — system checks, timing anomalies, user activity absence | `T1497` — Virtualization/Sandbox Evasion |
| `anti_debug` | Techniques used to detect or hinder debuggers | `T1622` — Debugger Evasion |
| `packer` | Indicators of packed or protected binaries | `T1027` — Obfuscated Files or Information |
| `network` | C2 communication, DNS, socket usage | `T1071` — Application Layer Protocol |
| `crypto` | Cryptographic constants and key scheduling patterns | `T1027` — Obfuscated Files or Information |
| `injection` | Process injection and code injection techniques | `T1055` — Process Injection |
| `persistence` | Mechanisms used to survive reboots | `T1547` — Boot or Logon Autostart Execution |
| `impair_defenses` | Techniques used to actively disable or modify security tools and defenses | `T1562` — Impair Defenses |

---

## Detection Types

### `imports`

Matches against the binary's **import table**. Each key is the exact API name as it appears in the IAT.

```json
"imports": {
    "GetSystemFirmwareTable": {
        "severity": "HIGH",
        "mitre": "T1497.001",
        "description": "Reads raw SMBIOS/ACPI tables to scan for VM artifact strings."
    },
    "GetTickCount": {
        "severity": "LOW",
        "combo_only": true,
        "mitre": "T1497.003",
        "description": "Ubiquitous; meaningful only in combination with Sleep for timing-based sandbox detection."
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `combo_only` | boolean | no | If `true`, the API is not flagged alone -- it is noted as a weak indicator and only escalates via a `combinations` match |
| `mitre` | string | no | MITRE ATT&CK sub-technique ID (e.g. `T1497.001`). Used in report findings and summary. |
| `description` | string | yes | Why this API is suspicious, and in what context |

**`combo_only` behavior:** The API still appears in the report when found, but is tagged as *"Standalone indicator weak -- meaningful only in combination"*. It will never appear alone as a `HIGH` or `CRITICAL` finding. Use `combo_only: true` when the API is so common in legitimate software that a standalone match would generate too many false positives.

---

### `strings`

Matches against **printable strings** found in the binary (ASCII and Unicode). This is the primary way to confirm *what* a suspicious API is actually doing -- an API like `RegOpenKeyEx` is generic, but the string `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` found alongside is conclusive.

```json
"strings": {
    "VMware, Inc.": {
        "severity": "HIGH",
        "mitre": "T1497.001",
        "description": "VMware vendor string -- registry or SMBIOS VM artifact."
    },
    "\\\\.\\VBoxMiniRdrDN": {
        "severity": "HIGH",
        "mitre": "T1497.001",
        "description": "VirtualBox device path used with CreateFileA for VM detection."
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `mitre` | string | no | MITRE ATT&CK sub-technique ID (e.g. `T1497.001`). Used in report findings and summary. |
| `description` | string | yes | What this string reveals about the binary's intent |

**Note on string detection vs API detection:** APIs tell you *what mechanism* is used. Strings tell you *what target* is being probed. Both together give a complete picture. Example: `RegOpenKeyEx` alone is noise, but `RegOpenKeyEx` + the string `VBoxGuest` in the same binary confirms registry-based VirtualBox detection.

---

### `byte_patterns`

Matches raw **byte sequences** in executable sections. Used for opcodes and instruction sequences that do not surface as imports or strings.

```json
"byte_patterns": {
    "rdtsc_timing": {
        "pattern": "0F 31",
        "severity": "HIGH",
        "mitre": "T1497.003",
        "description": "RDTSC instruction, used for timing-based VM/sandbox detection."
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | yes | Space-separated hex bytes. Use `??` as a single-byte wildcard. |
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `mitre` | string | no | MITRE ATT&CK sub-technique ID (e.g. `T1497.003`). Used in report findings and summary. |
| `description` | string | yes | What this byte sequence indicates |

---

### `combinations`

Triggers only when **all APIs listed in `requires`** are present in the import table simultaneously. This detects behavioral patterns -- individual APIs may be innocent, but their co-presence reveals intent.

Combination findings override the individual `combo_only` findings for the same APIs: instead of N weak individual findings, a single named finding is emitted at the combination's severity.

```json
"combinations": [
    {
        "name": "Sleep-skipping sandbox detection",
        "requires": ["GetTickCount", "Sleep"],
        "severity": "HIGH",
        "mitre": "T1497.003",
        "description": "Measures elapsed time around a Sleep call -- sandboxes that accelerate Sleep show an anomalously short delta."
    },
    {
        "name": "Registry-based VM detection",
        "requires": ["RegOpenKeyEx", "RegQueryValueEx"],
        "severity": "HIGH",
        "mitre": "T1497.001",
        "description": "Opens and queries registry keys -- likely reading VM-specific paths (VMware Tools, VBoxGuest)."
    }
]
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Human-readable name of the detected technique |
| `requires` | array | yes | All API names that must be present to trigger |
| `severity` | string | yes | Typically `HIGH` or `CRITICAL` for combinations |
| `mitre` | string | no | MITRE ATT&CK sub-technique ID (e.g. `T1497.001`). Used in report findings and summary. |
| `description` | string | yes | What the combination of APIs indicates |

**Important:** `combinations` only match on APIs from the import table. They do not cross-reference strings. If you want to confirm that `RegOpenKeyEx` is probing a *specific* VM path, that confirmation comes from the `strings` section independently -- the combination only tells you the mechanism is present.

---

## How the Four Detection Types Work Together

A complete detection for registry-based VMware detection would produce four independent findings:

| Type | Match | Finding |
|---|---|---|
| `imports` (combo_only) | `RegOpenKeyEx` | [LOW] weak indicator, noted |
| `imports` (combo_only) | `RegQueryValueEx` | [LOW] weak indicator, noted |
| `combinations` | `RegOpenKeyEx` + `RegQueryValueEx` | [HIGH] Registry-based VM detection |
| `strings` | `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` | [HIGH] VMware registry path confirmed |

The combination tells you *how*, the string tells you *what target*.

---

## Severity Levels

| Level | Meaning |
|---|---|
| `LOW` | Present in almost all binaries; only meaningful alongside other indicators |
| `MEDIUM` | Uncommon in legitimate software; warrants investigation |
| `HIGH` | Strongly indicative of malicious or evasive behavior |
| `CRITICAL` | Near-certain indicator, typically from a multi-API combination |

---

## Adding a New Category

If you need to add a new detection category:

1. Create a new file `signatures/<category>.json` with the base skeleton, using the current `SIGNATURES_VERSION` value from `utils/utils.py`:

```json
{
    "sig_version": 1,
    "imports": {},
    "strings": {},
    "byte_patterns": {},
    "combinations": []
}
```

2. Add the category name to `CATEGORIES` in `analyzer.py`.



---

## Validating signature files

To validate the integrity of the signature files, use the script [scripts/validate_signatures.py](../scripts/validate_signatures.py):

```bash
python scripts/validate_signatures.py
```

If the files are correct : it will display :

```bash
All 8 signature file(s) are valid.
 ```

Else, it will list the error :

```bash
Validation failed — 6 error(s):

  [anti_vm.json] imports.SetupDiEnumDeviceInfo: invalid severity 'ZMEDIUM'
  [injection.json] missing detection types (top-level keys): {'imports'}
  [injection.json] unknown top-level keys (typo?): {'import'}
  [injection.json] sig_version mismatch: expected 1, got 12
  [injection.json] imports.WriteProcessMemory: invalid severity 'MAEDaIUM'
  [injection.json] byte_patterns.process_hollowing_create_suspended: invalid byte token 'Y00' in pattern
```

---

## MITRE ATT&CK Version

Signatures in this project are mapped against **MITRE ATT&CK v16** (Enterprise, Windows platform).
Reference: https://attack.mitre.org

---

## Signature Sources

Signatures in this project are based on and cross-referenced against the following resources:

- [CheckPoint Evasions](https://evasions.checkpoint.com/)
- [Unprotect Project](https://www.unprotect.it/)
- [malapi.io](https://malapi.io/)

---

## Test Binary

### Anti-vm:
- [al-khaser](https://github.com/ayoubfaouzi/al-khaser)

**Signatures covered by al-khaser:**

| Category | `anti_vm.json` Signatures Tested |
|----------|-----------|
| **Registry** | `RegOpenKeyEx`, `RegQueryValueEx`, `RegEnumKeyEx` |
| **Firmware** | `GetSystemFirmwareTable`, `EnumSystemFirmwareTables` |
| **Device enumeration** | `SetupDiGetClassDevs`, `SetupDiEnumDeviceInfo`, `SetupDiGetDeviceRegistryProperty`, `DeviceIoControl` |
| **Network** | `GetAdaptersAddresses`, `GetAdaptersInfo`, `WNetGetProviderName` |
| **Process enumeration** | `CreateToolhelp32Snapshot`, `EnumProcesses`, `Process32First`, `Process32Next`, `Process32FirstW`, `Process32NextW`, `Module32First`, `Module32Next` |
| **Filesystem** | `GetFileAttributesA`, `GetFileAttributesW`, `FindFirstFileA`, `FindFirstFileW` |
| **Disk info** | `GetDiskFreeSpaceExA`, `GetDiskFreeSpaceExW`, `GetVolumeInformationA`, `GetVolumeInformationW` |
| **System info** | `GetSystemInfo`, `GlobalMemoryStatusEx`, `GetSystemMetrics`, `GetCursorPos`, `GetLastInputInfo`, `GetPwrCapabilities` |
| **Timing** | `GetTickCount`, `Sleep`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `WaitForSingleObject`, `WaitForMultipleObjects`, `NtDelayExecution`, `CreateWaitableTimer`, `timeSetEvent`, `IcmpSendEcho` |
| **Display** | `EnumDisplayDevicesA`, `Direct3DCreate9` |
| **Services** | `OpenSCManagerA`, `OpenSCManagerW`, `EnumServicesStatusW` |
| **WMI** | `CoInitializeEx`, `CoCreateInstance` |
| **User/Computer** | `GetUserNameA`, `GetUserNameW`, `GetComputerNameA`, `GetComputerNameW`, `GetComputerNameExW` |
| **Mutex** | `CreateMutexA`, `OpenMutexA` |
| **Device paths** | `CreateFileA`, `CreateFileW` |
| **Dynamic API** | `GetModuleHandle`, `GetProcAddress` |
| **License** | `NtQueryLicenseValue`, `IsNativeVhdBoot` |
| **Wine** | `MulDiv` |
| **Window** | `FindWindowA`, `EnumWindows` |
| **OpenProcess** | `OpenProcess` |
| **Strings** | `VMware, Inc.`, `VMware`, `VMwareVMware`, `VBOX`, `VBoxVBoxVBox`, `VBoxGuest`, `VBoxService`, `VBoxTrayToolWndClass`, `vmtoolsd.exe`, `vboxservice.exe`, `vmwaretray.exe`, `vmwareuser.exe`, `vmacthlp.exe`, `vboxtray.exe`, `VBoxControl.exe`, `qemu-ga.exe`, `prl_cc.exe`, `sbiedll.dll`, `snxhk.dll`, `pstorec.dll`, `dir_watch.dll`, `vmcheck.dll`, `api_log.dll`, `Kernel-VMDetection-Private`, `sandbox`, `malware`, `virus`, `SANDBOX`, `CUCKOO`, `QEMU`, `VIRTUAL HD`, `Hyper-V`, `Microsoft Hv`, `KVMKVMKVM`, `XenVMMXenVMM`, `prl hyperv`, `wine_get_unix_file_name`, `wine_get_host_version`, `VMware SVGA II`, `VirtualBox Graphics Adapter`, `VBOX HARDDISK`, `VMware Virtual disk` |
| **Paths** | `C:\Windows\System32\drivers\VBoxMouse.sys`, `C:\Windows\System32\drivers\VBoxGuest.sys`, `C:\Windows\System32\drivers\VBoxSF.sys`, `C:\Windows\System32\drivers\VBoxVideo.sys`, `C:\Windows\System32\vboxdisp.dll`, `C:\Windows\System32\vboxhook.dll`, `C:\Windows\System32\vboxmrxnp.dll`, `C:\Windows\System32\drivers\vmhgfs.sys`, `C:\Windows\System32\drivers\vmmouse.sys`, `C:\Windows\System32\drivers\vmmemctl.sys`, `C:\Windows\System32\drivers\vmci.sys`, `HKLM\SOFTWARE\VMware, Inc.\VMware Tools`, `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`, `HKLM\SYSTEM\CurrentControlSet\Services\VBoxGuest`, `HKLM\SYSTEM\ControlSet001\Services\VBoxSF`, `HKLM\HARDWARE\ACPI\DSDT\VBOX__`, `HKLM\HARDWARE\ACPI\FADT\VBOX__`, `HKLM\HARDWARE\ACPI\RSDT\VBOX__`, `HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\Disk&Ven_VMware_&Prod_VMware_Virtual_S`, `\\.\VBoxMiniRdrDN`, `\\.\pipe\VBoxTrayIPC`, `\\.\VBoxGuest`, `\\.\HGFS`, `\\.\vmci` |
| **Byte patterns** | `cpuid_check`, `cpuid_hypervisor_leaf`, `rdtsc_timing`, `vmware_io_port`, `sidt_check`, `sgdt_check`, `sldt_check`, `str_check` |

---

### Anti-debug:
- [al-khaser](https://github.com/ayoubfaouzi/al-khaser)

**Signatures covered by al-khaser:**

| Category | `anti_debug.json` Signatures Tested |
|----------|-----------|
| **Basic debugger checks** | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `RtlQueryProcessHeapInformation`, `RtlQueryProcessDebugInformation`, `NtQuerySystemInformation`, `NtQueryObject`, `NtClose`, `HeapWalk`, `DebugBreak`, `GetThreadContext`, `GetCurrentThread`, `NtQueryVirtualMemory` |
| **Exception handling** | `SetUnhandledExceptionFilter`, `RaiseException`, `AddVectoredExceptionHandler`, `RemoveVectoredExceptionHandler` |
| **Anti-attach** | `NtSetInformationThread`, `DebugActiveProcess`, `CreateProcess`, `DbgSetDebugFilterState`, `NtSetDebugFilterState` |
| **Timing** | `GetLocalTime`, `GetTickCount`, `QueryPerformanceCounter`, `SwitchToThread`, `NtYieldExecution` |
| **Window detection** | `FindWindowA`, `FindWindowW`, `FindWindowExA`, `FindWindowExW`, `GetShellWindow`, `GetWindowThreadProcessId` |
| **OutputDebugString** | `OutputDebugStringA`, `SetLastError`, `GetLastError` |
| **Memory manipulation** | `WriteProcessMemory`, `VirtualAlloc`, `VirtualProtect`, `ReadProcessMemory`, `GetWriteWatch`, `Toolhelp32ReadProcessMemory` |
| **Process/Thread** | `OpenProcess`, `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `TerminateProcess` |
| **Dynamic API** | `LoadLibraryA`, `LoadLibraryW`, `GetProcAddress`, `GetModuleHandle`, `CreateFileA`, `CreateFileW`, `GetModuleFileNameA`, `GetModuleFileNameW` |
| **Strings** | `OLLYDBG`, `WinDbgFrameClass`, `ID`, `ObsidianGUI`, `Qt5QWindowIcon`, `Zeta Debugger`, `Rock Debugger`, `antidbg`, `x64dbg`, `ollydbg.exe`, `x64dbg.exe`, `x32dbg.exe`, `windbg.exe`, `idag.exe`, `idag64.exe`, `idaw.exe`, `idaw64.exe`, `immunitydebugger.exe`, `petools.exe`, `lordpe.exe`, `ProcessHacker.exe`, `dbgview.exe`, `ThreadHideFromDebugger`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `ntdll.dll`, `DbgBreakPoint`, `DbgUiRemoteBreakin`, `CsrGetProcessId` |
| **Byte patterns** | `peb_beingdebugged_x86`, `peb_beingdebugged_x64`, `ntglobalflag_x86`, `ntglobalflag_x64`, `kuser_shared_data_x86`, `kuser_shared_data_x64`, `rdtsc_timing`, `int2ah_timing`, `int3_long`, `int2d`, `ice_undocumented`, `popf_trap_flag`, `rep_prefix_anti_trace`, `pushss_popss_pushf`, `software_bp_scan_cc`, `hardware_bp_dr0_check_x86` |

---

### Injection:

Test binaries from [atomic-red-team](https://github.com/redcanaryco/atomic-red-team.git)

```bash
git clone https://github.com/redcanaryco/atomic-red-team.git
# Binaries are located in:
#   atomics/T1055/bin/x64/
#   atomics/T1055.002/bin/
#   atomics/T1055.004/bin/x64/
#   atomics/T1055.012/bin/x64/
#   atomics/T1055.015/bin/
```

| Technique                  | Binary                    | `injection.json` Signatures Tested                                                       |
| -------------------------- | ------------------------- | ---------------------------------------------------------------------------------------- |
| Process Hollowing          | `CreateProcess.exe`       | `CreateProcessW`, `NtUnmapViewOfSection`, `SetThreadContext`, `pe_magic_embedded`        |
| APC Injection (Early Bird) | `EarlyBird.exe`           | `QueueUserAPC`, `CreateProcessA`, `VirtualAllocEx`, `WriteProcessMemory`, `ResumeThread` |
| Native APC                 | `NtQueueApcThreadEx.exe`  | `NtQueueApcThreadEx`, `NtQueueApcThread`                                                 |
| Section-based injection    | `InjectView.exe`          | `NtCreateSection`, `NtMapViewOfSection`                                                  |
| Native remote thread       | `RtlCreateUserThread.exe` | `RtlCreateUserThread`, `VirtualAllocEx`, `WriteProcessMemory`, `VirtualProtectEx`        |
| ListPlanting               | `ListPlanting.exe`        | `FindWindow`, `SendMessage`, `PostMessage`, `VirtualAllocEx`                             |
| PE Injection               | `RedInjection.exe`        | `pe_magic_embedded` (byte pattern)                                                       |

---

### Persistence:

Tested against real-world malware samples from [MalwareBazaar](https://bazaar.abuse.ch/):

| Family | SHA256 | Techniques confirmed |
|---|---|---|
| PlugX | `3cdd33dea12f21a4f222eb060e1e8ca8a20d5f6ca0fd849715f125b973f3a257` | none (weak evidence for T1547.001/T1543.003 via strings only) |
| Berbew/Padodor (sample 1) | `3ea33da21e2745965c0f2884a7050635d9e72b6f72df48bb763ebbc810a88aca` | T1547.001, T1547.004 |
| Berbew/Padodor (sample 2) | `328e0c70f0471edaa9e705719a3f52eb4ad537b3f3926a1189776ec3fc6a8e93` | T1547.001 (×2 variants), T1547.004 |
| Berbew/Padodor (sample 3) | `43483130d3303ff2d67946e2b30b77b0e9b785ab9b56a65f82d001d4c8a77519` | T1547.001, T1547.004 |
| Hupigon | `465d3aac3ca4daa9ad4de04fcb999f358396efd7abceed9701c9c28c23c126db` | T1547.001, T1547.004, T1543.003 (×2) |
| Ramnit | `ee9378542050d13b1028b443f214d363dac7d11c1229e7e9054efde251d3e36b` | T1547.001, T1547.004 |

3 of 17 targeted sub-techniques were confirmed via triggered combinations, cross-validated across 4 independent families:

| Sub-technique | Description | Status |
|---|---|---|
| `T1547.001` | Registry Run Key | Confirmed |
| `T1547.004` | Winlogon Helper DLL | Confirmed |
| `T1543.003` | Windows Service (including the "existing service hijack" variant, confirmed on Hupigon) | Confirmed |

Remaining sub-techniques (`T1546.003/.009/.010/.012/.015`, `T1053.005`, `T1197`, `T1547.002/.003/.005/.009/.014`) were not observed in this sample set.