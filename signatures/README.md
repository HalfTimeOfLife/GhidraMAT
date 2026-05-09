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
    "imports": {},
    "strings": {},
    "byte_patterns": {},
    "combinations": []
}
```

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
| `pattern` | string | yes | Space-separated hex bytes. |
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

## How the Three Types Work Together

A complete detection for registry-based VMware detection would produce three independent findings:

| Type | Match | Finding |
|---|---|---|
| `imports` (combo_only) | `RegOpenKeyEx` | [LOW] weak indicator, noted |
| `imports` (combo_only) | `RegQueryValueEx` | [LOW] weak indicator, noted |
| `combinations` | `RegOpenKeyEx` + `RegQueryValueEx` | [HIGH] Registry-based VM detection |
| `strings` | `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` | [HIGH] VMware registry path confirmed |

The combination tells you *how*, the string tells you *what target*.

---

## Adding a New Category

If you need to add a new detection category:

1. Create a new file `signatures/<category>.json` with the base skeleton:

```json
{
    "imports": {},
    "strings": {},
    "byte_patterns": {},
    "combinations": []
}
```

2. Add the category name to `CATEGORIES` in `analyzer.py`.

---

## Severity Levels

| Level | Meaning |
|---|---|
| `LOW` | Present in almost all binaries; only meaningful alongside other indicators |
| `MEDIUM` | Uncommon in legitimate software; warrants investigation |
| `HIGH` | Strongly indicative of malicious or evasive behavior |
| `CRITICAL` | Near-certain indicator, typically from a multi-API combination |

---
## MITRE ATT&CK Version

Signatures in this project are mapped against **MITRE ATT&CK v16** (Enterprise, Windows platform).
Reference : https://attack.mitre.org

---

## Signature Sources

Signatures in this project are based on and cross-referenced against the following resources:
 
- [CheckPoint Evasions](https://evasions.checkpoint.com/)
- [Unprotect Project](https://www.unprotect.it/)
- [al-khaser](https://github.com/ayoubfaouzi/al-khaser)

---