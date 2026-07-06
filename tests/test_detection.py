"""tests/test_detection.py

Tests for utils.detection.analyze
"""

import json
import pytest
 
from tests.fakes import (
    FakeContext, FakeSymbolTable, FakeListing, FakeRefManager,
    FakeFuncManager, FakeSymbol, FakeData, FakeReference, FakeAddress,
    FakeFunction, FakeInstruction, FakeProgram, FakeMonitor
)
from utils.detection import analyze

# -------------------------------------------------------------------
# --- helpers ---
# -------------------------------------------------------------------
 
 
def write_signatures(tmp_path, category, data):
    """Helper to write a signature JSON file for a given category."""
    path = tmp_path / f"{category}.json"
    path.write_text(json.dumps(data), encoding="utf-8")

# -------------------------------------------------------------------
# --- imports detection ---
# -------------------------------------------------------------------

def test_analyze_detects_import(tmp_path, monkeypatch):
    """analyze() should produce a Finding when an import is present in the binary."""
    signatures = {
        "sig_version": 1,
        "imports": {
            "CreateToolhelp32Snapshot": {
                "severity": "MEDIUM",
                "mitre": "T1497.001",
                "description": "Creates a process/module snapshot."
            }
        },
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    addr = FakeAddress(0x1000)
    symbol = FakeSymbol("CreateToolhelp32Snapshot", addr)
    func = FakeFunction("main", FakeAddress(0x1000))

    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[symbol]),
        ref_manager=FakeRefManager(refs_by_address={addr: [FakeReference(addr)]}),
        func_manager=FakeFuncManager(function_by_address={addr: func})
    )

    findings = analyze(context, "anti_vm")

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "anti_vm"
    assert f.type == "imports"
    assert f.name == "CreateToolhelp32Snapshot"
    assert f.severity == "MEDIUM"
    assert f.mitre == "T1497.001"
    assert f.combo_only is False
    assert f.xrefs == [addr]
    assert f.xref_labels == ["0x1000 (main)"]


def test_analyze_skips_import_not_present(tmp_path, monkeypatch):
    """analyze() should not produce a Finding when the import is absent from the binary."""
    signatures = {
        "sig_version": 1,
        "imports": {
            "CreateToolhelp32Snapshot": {
                "severity": "MEDIUM",
                "mitre": "T1497.001",
                "description": "Creates a process/module snapshot."
            }
        },
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[])
    )

    findings = analyze(context, "anti_vm")

    assert findings == []


def test_analyze_import_combo_only_flag_set(tmp_path, monkeypatch):
    """analyze() should produce a Finding with the combo_only flag set when the import is present."""
    signatures = {
        "sig_version": 1,
        "imports": {
            "GetTickCount": {
                "severity": "LOW",
                "combo_only": True,
                "mitre": "T1497.003",
                "description": "Ubiquitous; meaningful only in combination with Sleep."
            }
        },
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    addr = FakeAddress(0x1000)
    symbol = FakeSymbol("GetTickCount", addr)
    func = FakeFunction("main", FakeAddress(0x1000))
    
    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[symbol]),
        ref_manager=FakeRefManager(refs_by_address={addr: [FakeReference(addr)]}),
        func_manager=FakeFuncManager(function_by_address={addr: func})
    )
    
    findings = analyze(context, "anti_vm")
    
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "anti_vm"
    assert f.type == "imports"
    assert f.name == "GetTickCount"
    assert f.severity == "LOW"
    assert f.mitre == "T1497.003"
    assert f.combo_only is True

# -------------------------------------------------------------------
# --- strings detection ---
# -------------------------------------------------------------------

def test_analyze_detects_string(tmp_path, monkeypatch):
    """analyze() should produce a Finding when a signed string is defined in the binary."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {
            "VMware, Inc.": {
                "severity": "HIGH",
                "mitre": "T1497.001",
                "description": "VMware vendor string."
            }
        },
        "byte_patterns": {},
        "combinations": []
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    addr = FakeAddress(0x1000)
    data = FakeData("VMware, Inc.", addr)
    context = FakeContext(
        listing=FakeListing(data=[data]),
        ref_manager=FakeRefManager(refs_by_address={addr: [FakeReference(addr)]})
    )
    
    findings = analyze(context, "anti_vm")
    
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "anti_vm"
    assert f.type == "strings"
    assert f.name == "VMware, Inc."
    assert f.severity == "HIGH"
    assert f.mitre == "T1497.001"
    
    
def test_analyze_skips_string_not_present(tmp_path, monkeypatch):
    """analyze() should not produce a Finding when the signed string is absent from the binary."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {
            "VMware, Inc.": {
                "severity": "HIGH",
                "mitre": "T1497.001",
                "description": "VMware vendor string."
            }
        },
        "byte_patterns": {},
        "combinations": []
    }
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    context = FakeContext(listing=FakeListing(data=[]))
    
    findings = analyze(context, "anti_vm")
    
    assert findings == []

# -------------------------------------------------------------------
# --- byte_patterns detection ---
# -------------------------------------------------------------------

def test_analyze_detects_byte_pattern(tmp_path, monkeypatch):
    """analyze() should produce a Finding when a signed byte pattern matches an instruction."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {
            "rdtsc_timing": {
                "pattern": "0F 31",
                "severity": "HIGH",
                "mitre": "T1497.003",
                "description": "RDTSC instruction, used for timing-based VM/sandbox detection."
            }
        },
        "combinations": []
    }

    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    addr = FakeAddress(0x1000)
    func = FakeFunction("check_timing", FakeAddress(0x1000))
    instr = FakeInstruction(min_address=addr, byte_values=[0x0F, 0x31])

    context = FakeContext(
        program=FakeProgram(listing=FakeListing(instructions=[instr])),
        func_manager=FakeFuncManager(function_by_address={addr: func})
    )

    findings = analyze(context, "anti_vm")

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "anti_vm"
    assert f.type == "byte_patterns"
    assert f.name == "rdtsc_timing"
    assert f.severity == "HIGH"
    assert f.mitre == "T1497.003"
    assert findings[0].xrefs == [addr]


def test_analyze_byte_pattern_groups_multiple_matches_into_one_finding(tmp_path, monkeypatch):
    """analyze() should group every occurrence of the same byte pattern into a single Finding."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {
            "rdtsc_timing": {
                "pattern": "0F 31",
                "severity": "HIGH",
                "mitre": "T1497.003",
                "description": "RDTSC instruction, used for timing-based VM/sandbox detection."
            }
        },
        "combinations": []
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    addr1 = FakeAddress(0x1000)
    addr2 = FakeAddress(0x2000)
    func1 = FakeFunction("check_timing_1", addr1)
    func2 = FakeFunction("check_timing_2", addr2)
    instr1 = FakeInstruction(min_address=addr1, byte_values=[0x0F, 0x31])
    instr2 = FakeInstruction(min_address=addr2, byte_values=[0x0F, 0x31])
    
    context = FakeContext(
        program=FakeProgram(listing=FakeListing(instructions=[instr1, instr2])),
        func_manager=FakeFuncManager(function_by_address={addr1: func1, addr2: func2})
    )
    
    findings = analyze(context, "anti_vm")
    
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "anti_vm"
    assert f.type == "byte_patterns"
    assert f.name == "rdtsc_timing"
    assert f.severity == "HIGH"
    assert f.mitre == "T1497.003"
    assert set(f.xrefs) == {addr1, addr2}
    assert set(f.xref_labels) == {"0x1000 (check_timing_1)", "0x2000 (check_timing_2)"}


def test_analyze_skips_byte_pattern_not_present(tmp_path, monkeypatch):
    """analyze() should not produce a Finding when no instruction matches the signed pattern."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {
            "rdtsc_timing": {
                "pattern": "0F 31",
                "severity": "HIGH",
                "mitre": "T1497.003",
                "description": "RDTSC instruction, used for timing-based VM/sandbox detection."
            }
        },
        "combinations": []
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    addr = FakeAddress(0x1000)
    func = FakeFunction("func", addr)
    instr = FakeInstruction(min_address=addr, byte_values=[0x90, 0x90])  # NOPs, not RDTSC
    
    context = FakeContext(
        program=FakeProgram(listing=FakeListing(instructions=[instr])),
        func_manager=FakeFuncManager(function_by_address={addr: func})
    )
    
    findings = analyze(context, "anti_vm")
    
    assert findings == []

# -------------------------------------------------------------------
# --- combinations detection ---
# -------------------------------------------------------------------

def test_analyze_detects_combination_when_all_requires_present(tmp_path, monkeypatch):
    """
    analyze() should produce a combination Finding alongside the individual import
    Findings when every required import is present.
    """
    signatures = {
        "sig_version": 1,
        "imports": {
            "GetTickCount": {"severity": "LOW", "combo_only": True, "description": "..."},
            "Sleep": {"severity": "LOW", "combo_only": True, "description": "..."}
        },
        "strings": {},
        "byte_patterns": {},
        "combinations": [
            {
                "name": "Sleep-skipping sandbox detection",
                "requires": ["GetTickCount", "Sleep"],
                "severity": "HIGH",
                "mitre": "T1497.003",
                "description": "Measures elapsed time around a Sleep call."
            }
        ]
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    addr1 = FakeAddress(0x1000)
    addr2 = FakeAddress(0x2000)
    symbol1 = FakeSymbol("GetTickCount", addr1)
    symbol2 = FakeSymbol("Sleep", addr2)
    func1 = FakeFunction("main", addr1)
    func2 = FakeFunction("main", addr2)
    
    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[symbol1, symbol2]),
        ref_manager=FakeRefManager(refs_by_address={addr1: [FakeReference(addr1)], addr2: [FakeReference(addr2)]}),
        func_manager=FakeFuncManager(function_by_address={addr1: func1, addr2: func2})
    )
    
    findings = analyze(context, "anti_vm")
    
    assert len(findings) == 3
    
    for f in findings:
        if f.name == "GetTickCount":
            assert f.category == "anti_vm"
            assert f.type == "imports"
            assert f.severity == "LOW"
            assert f.combo_only is True
        elif f.name == "Sleep":
            assert f.category == "anti_vm"
            assert f.type == "imports"
            assert f.severity == "LOW"
            assert f.combo_only is True
        elif f.name == "Sleep-skipping sandbox detection":
            assert f.category == "anti_vm"
            assert f.type == "combinations"
            assert f.severity == "HIGH"
            assert f.mitre == "T1497.003"
            assert f.xrefs == []
            assert set(f.requirements) == {"GetTickCount", "Sleep"}
        else:
            pytest.fail(f"Unexpected finding name: {f.name}")


def test_analyze_skips_combination_when_partial_requires_present(tmp_path, monkeypatch):
    """analyze() should not produce a combination Finding when only some required imports are present."""
    signatures = {
        "sig_version": 1,
        "imports": {
            "GetTickCount": {"severity": "LOW", "combo_only": True, "description": "..."}
        },
        "strings": {},
        "byte_patterns": {},
        "combinations": [
            {
                "name": "Sleep-skipping sandbox detection",
                "requires": ["GetTickCount", "Sleep"],
                "severity": "HIGH",
                "mitre": "T1497.003",
                "description": "Measures elapsed time around a Sleep call."
            }
        ]
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))
    
    addr = FakeAddress(0x1000)
    symbol = FakeSymbol("GetTickCount", addr)
    func = FakeFunction("main", addr)
    
    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[symbol]),
        ref_manager=FakeRefManager(refs_by_address={addr: [FakeReference(addr)]}),
        func_manager=FakeFuncManager(function_by_address={addr: func})
    )
    
    findings = analyze(context, "anti_vm")
    
    assert len(findings) == 1
    f = findings[0]
    assert f.name == "GetTickCount"
    assert f.category == "anti_vm"
    assert f.type == "imports"
    assert f.severity == "LOW"
    assert f.combo_only is True


def test_analyze_combination_finding_has_no_xrefs(tmp_path, monkeypatch):
    """Combination findings never carry xrefs."""
    signatures = {
        "sig_version": 1,
        "imports": {
            "GetTickCount": {"severity": "LOW", "combo_only": True, "description": "..."},
            "Sleep": {"severity": "LOW", "combo_only": True, "description": "..."}
        },
        "strings": {},
        "byte_patterns": {},
        "combinations": [
            {
                "name": "Sleep-skipping sandbox detection",
                "requires": ["GetTickCount", "Sleep"],
                "severity": "HIGH",
                "description": "Measures elapsed time around a Sleep call."
            }
        ]
    }

    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    symbol1 = FakeSymbol("GetTickCount", FakeAddress(0x1000))
    symbol2 = FakeSymbol("Sleep", FakeAddress(0x2000))

    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[symbol1, symbol2])
    )

    findings = analyze(context, "anti_vm")

    combo_finding = next(f for f in findings if f.type == "combinations")
    assert combo_finding.xrefs == []
    


# -------------------------------------------------------------------
# --- category / signature loading ---
# -------------------------------------------------------------------

def test_analyze_uses_correct_category_in_findings(tmp_path, monkeypatch):
    """Every Finding produced by analyze() should carry the category it was called with."""
    signatures = {
        "sig_version": 1,
        "imports": {
            "GetTickCount": {"severity": "LOW", "combo_only": True, "description": "..."}
        },
        "strings": {
            "VMware, Inc.": {"severity": "HIGH", "description": "..."}
        },
        "byte_patterns": {
            "rdtsc_timing": {"pattern": "0F 31", "severity": "HIGH", "description": "..."}
        },
        "combinations": [
            {
                "name": "Some combo",
                "requires": ["GetTickCount"],
                "severity": "HIGH",
                "description": "..."
            }
        ]
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    addr_import = FakeAddress(0x1000)
    addr_string = FakeAddress(0x2000)
    addr_instr = FakeAddress(0x3000)

    symbol = FakeSymbol("GetTickCount", addr_import)
    data = FakeData("VMware, Inc.", addr_string)
    instr = FakeInstruction(min_address=addr_instr, byte_values=[0x0F, 0x31])
    func = FakeFunction("main", FakeAddress(0x1000))
    
    context = FakeContext(
        symbol_table=FakeSymbolTable(symbols=[symbol]),
        listing=FakeListing(data=[data]),
        program=FakeProgram(listing=FakeListing(instructions=[instr])),
        ref_manager=FakeRefManager(refs_by_address={
            addr_import: [FakeReference(addr_import)],
            addr_string: [FakeReference(addr_string)]
        }),
        func_manager=FakeFuncManager(function_by_address={
            addr_import: func, addr_string: func, addr_instr: func
        })
    )
    
    findings = analyze(context, "anti_vm")

    assert len(findings) == 4
    types_found = {f.type for f in findings}
    assert types_found == {"imports", "strings", "byte_patterns", "combinations"}
    for f in findings:
        assert f.category == "anti_vm"


def test_analyze_empty_signatures_produces_no_findings(tmp_path, monkeypatch):
    """analyze() should return an empty list when the signature file has no entries at all."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }
    
    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    context = FakeContext()

    findings = analyze(context, "anti_vm")

    assert findings == []

# -------------------------------------------------------------------
# --- monitor interaction ---
# -------------------------------------------------------------------

def test_analyze_sets_monitor_message_when_monitor_present(tmp_path, monkeypatch):
    """analyze() should call monitor.setMessage() with the category name when a monitor is present."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }

    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    monitor = FakeMonitor()
    context = FakeContext(monitor=monitor)

    analyze(context, "anti_vm")

    assert len(monitor.messages) == 1
    assert "anti_vm" in monitor.messages[0]


def test_analyze_skips_monitor_message_when_monitor_none(tmp_path, monkeypatch):
    """analyze() should not attempt to call setMessage() when no monitor is provided."""
    signatures = {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }

    write_signatures(tmp_path, "anti_vm", signatures)
    monkeypatch.setattr("utils.detection.SIG_PATH", str(tmp_path))

    context = FakeContext(monitor=None)

    findings = analyze(context, "anti_vm")

    assert findings == []