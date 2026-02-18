# Signatures format

GhidraMAT's detection logic is fully driven by [signatures.json](signatures.json). This document explains the structure and available fields.

## Top-level Structure

Signatures are organized by **category**, each containing four detection types:

```json
{
    "category": {
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

Matches against the binary's **import table**.
```json
"imports": {
    "IsDebuggerPresent": {
        "severity": "HIGH",
        "description": "Checks if the process is being debugged via the PEB.",
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `description` | string | yes | Human-readable explanation of why this is suspicious |

---

### `strings`

Matches against **printable strings** found in the binary.

```json
"strings": {
    "String": {
        "severity": "HIGH",
        "description": "Description",
    }
}
```
| Field | Type | Required | Description |
|---|---|---|---|
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `description` | string | yes | Human-readable explanation of why this is suspicious |

Same fields as `imports`. The key is the exact string to match (case-sensitive).

---

### `byte_patterns`

Matches raw **byte sequences** anywhere in the binary's executable sections.

```json
"byte_patterns": {
    "cpuid_hypervisor_check": {
        "pattern": "0F A2 83 F8 01",
        "severity": "HIGH",
        "description": "CPUID instruction followed by hypervisor bit check (ECX bit 31).",
    }
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | yes | Space-separated hex bytes. Wildcards: use `??` for any byte |
| `severity` | string | yes | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `description` | string | yes | What this byte sequence indicates |

---

### `combinations`

A combination triggers only when **all APIs listed in `requires`** are present in the binary's import table simultaneously.

Combination findings always **override** the individual findings from `imports` for the same APIs.

```json
"combinations": [
    {
        "name": "Classic DLL Injection",
        "requires": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "severity": "CRITICAL",
        "description": "Full remote process injection chain detected.",
    }
]
```

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Human-readable name of the detected technique |
| `requires` | array | yes | All API names that must be present to trigger |
| `severity` | string | yes | Always set to `HIGH` or `CRITICAL` for combinations |
| `description` | string | yes | What the combination of APIs indicates |

---

## Severity Levels

| Level | Meaning |
|---|---|
| `LOW` | Suspicious in context, common in legitimate software |
| `MEDIUM` | Uncommon in legitimate software, warrants investigation |
| `HIGH` | Strongly indicative of malicious behavior |
| `CRITICAL` | Near-certain indicator, typically from a combination match |

---