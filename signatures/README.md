# Signatures Format

GhidraMAT's detection logic is fully driven by `signatures.json`. This document explains the structure and available fields.

---

## Top-level Structure

Signatures are organized by **category**, each containing four detection types:

```json
{
    "<category>": {
        "imports": {},
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }
}
```

| Category | Description |
|---|---|
| `anti_debug` | Techniques used to detect or hinder debuggers |
| `anti_vm` | Techniques used to detect virtualized environments |
| `packer` | Indicators of packed or protected binaries |
| `network` | C2 communication, DNS, socket usage |
| `crypto` | Cryptographic constants and key scheduling patterns |
| `injection` | Process injection and code injection techniques |
| `persistence` | Mechanisms used to survive reboots |
| `evasion` | Sandbox evasion and timing-based tricks |

---

## Detection Types

### `imports`

Matches against the binary's **import table**. Each key is the exact API name as it appears in the IAT.

```json
"imports": {
    "GetSystemFirmwareTable": {
        "severity": "HIGH",
        "description": "Reads raw SMBIOS/ACPI tables to scan for VM artifact strings."
    },
    "GetTickCount": {
        "severity": "LOW",
        "combo_only": true,
        "description": "Ubiquitous; meaningful only in combination with Sleep for timing-based sandbox detection."
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `combo_only` | boolean | no | If `true`, the API is not flagged alone — it is noted as a weak indicator and only escalates via a `combinations` match |
| `description` | string | yes | Why this API is suspicious, and in what context |

**`combo_only` behavior:** The API still appears in the report when found, but is tagged as *"Standalone indicator weak — meaningful only in combination"*. It will never appear alone as a `HIGH` or `CRITICAL` finding. Use `combo_only: true` when the API is so common in legitimate software that a standalone match would generate too many false positives.

---

### `strings`

Matches against **printable strings** found in the binary (ASCII and Unicode). This is the primary way to confirm *what* a suspicious API is actually doing — an API like `RegOpenKeyEx` is generic, but the string `HKLM\SOFTWARE\VMware, Inc.\VMware Tools` found alongside is conclusive.

```json
"strings": {
    "VMware, Inc.": {
        "severity": "HIGH",
        "description": "VMware vendor string — registry or SMBIOS VM artifact."
    },
    "\\\\.\\VBoxMiniRdrDN": {
        "severity": "HIGH",
        "description": "VirtualBox device path used with CreateFileA for VM detection."
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `description` | string | yes | What this string reveals about the binary's intent |

**Note on string detection vs API detection:** APIs tell you *what mechanism* is used. Strings tell you *what target* is being probed. Both together give a complete picture. Example: `RegOpenKeyEx` alone is noise, but `RegOpenKeyEx` + the string `VBoxGuest` in the same binary confirms registry-based VirtualBox detection.

---

### `byte_patterns`

Matches raw **byte sequences** in executable sections. Used for opcodes and instruction sequences that do not surface as imports or strings.

```json
"byte_patterns": {
    "rdtsc_timing": {
        "pattern": "0F 31 ?? ?? ?? ?? 0F 31",
        "severity": "HIGH",
        "description": "Two consecutive RDTSC instructions — timing delta check for VM/sandbox detection."
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | yes | Space-separated hex bytes. Use `??` for wildcard bytes |
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `description` | string | yes | What this byte sequence indicates |

---

### `combinations`

Triggers only when **all APIs listed in `requires`** are present in the import table simultaneously. This detects behavioral patterns — individual APIs may be innocent, but their co-presence reveals intent.

Combination findings override the individual `combo_only` findings for the same APIs: instead of N weak individual findings, a single named finding is emitted at the combination's severity.

```json
"combinations": [
    {
        "name": "Sleep-skipping sandbox detection",
        "requires": ["GetTickCount", "Sleep"],
        "severity": "HIGH",
        "description": "Measures elapsed time around a Sleep call — sandboxes that accelerate Sleep show an anomalously short delta."
    },
    {
        "name": "Registry-based VM detection",
        "requires": ["RegOpenKeyEx", "RegQueryValueEx"],
        "severity": "HIGH",
        "description": "Opens and queries registry keys — likely reading VM-specific paths (VMware Tools, VBoxGuest)."
    }
]
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Human-readable name of the detected technique |
| `requires` | array | yes | All API names that must be present to trigger |
| `severity` | string | yes | Typically `HIGH` or `CRITICAL` for combinations |
| `description` | string | yes | What the combination of APIs indicates |

**Important:** `combinations` only match on APIs from the import table. They do not cross-reference strings. If you want to confirm that `RegOpenKeyEx` is probing a *specific* VM path, that confirmation comes from the `strings` section independently — the combination only tells you the mechanism is present.

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

## Severity Levels

| Level | Meaning |
|---|---|
| `LOW` | Present in almost all binaries; only meaningful alongside other indicators |
| `MEDIUM` | Uncommon in legitimate software; warrants investigation |
| `HIGH` | Strongly indicative of malicious or evasive behavior |
| `CRITICAL` | Near-certain indicator, typically from a multi-API combination |

---