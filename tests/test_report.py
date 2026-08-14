"""tests/test_report.py

Tests for core.report
"""

import json
import os
from datetime import datetime, timezone

import pytest

from core import report
from core.finding import Finding

# -------------------------------------------------------------------
# --- fixtures / helpers ---
# -------------------------------------------------------------------


def make_finding(**kwargs):
    """Create a Finding with sensible defaults, overridable via kwargs."""
    defaults = {
        "category": "anti_vm",
        "type_of_technique": "imports",
        "name": "TestAPI",
        "severity": "HIGH",
        "description": "Test description",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


@pytest.fixture
def program_info():
    return {
        "name": "test_binary.exe",
        "path": "C:\\samples\\test_binary.exe",
        "format": "PE",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "date": "Tue Jul 07 00:00:00 CEST 2026",
    }


@pytest.fixture
def now():
    return datetime(2026, 7, 7, 12, 30, 45, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def patch_reports_dir(tmp_path, monkeypatch):
    """Redirect REPORTS_DIR to a temp directory so tests never touch reports/."""
    monkeypatch.setattr(report, "REPORTS_DIR", str(tmp_path))
    return tmp_path


# -------------------------------------------------------------------
# --- generate_json ---
# -------------------------------------------------------------------


def test_generate_json_top_level_keys(program_info, now):
    """The json report should contain exactly the expected top-level keys."""
    findings = [make_finding()]
    filename = report.generate_json(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert set(data.keys()) == {"meta", "program", "summary", "findings"}


def test_generate_json_summary_by_severity(program_info, now):
    """The json report should correctly count findings per severity level."""
    findings = [
        make_finding(severity="HIGH"),
        make_finding(severity="HIGH"),
        make_finding(severity="LOW"),
    ]
    filename = report.generate_json(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert data["summary"]["by_severity"] == {
        "CRITICAL": 0,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 1,
    }


def test_generate_json_summary_by_category(program_info, now):
    """The json report should break down totals."""
    findings = [
        make_finding(category="anti_vm", type_of_technique="imports", severity="HIGH"),
        make_finding(
            category="anti_vm", type_of_technique="strings", severity="MEDIUM"
        ),
        make_finding(
            category="anti_debug", type_of_technique="combinations", severity="CRITICAL"
        ),
    ]
    filename = report.generate_json(
        findings, program_info, ["anti_vm", "anti_debug"], now
    )

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert data["summary"]["by_category"]["anti_vm"]["total"] == 2
    assert data["summary"]["by_category"]["anti_vm"]["by_type"]["imports"] == 1
    assert data["summary"]["by_category"]["anti_vm"]["by_type"]["strings"] == 1
    assert data["summary"]["by_category"]["anti_debug"]["total"] == 1
    assert data["summary"]["by_category"]["anti_debug"]["by_severity"]["CRITICAL"] == 1


def test_generate_json_empty_category_present(program_info, now):
    """In the json report, a category with no findings should still appear with zeroed-out counts."""
    findings = [make_finding(category="anti_vm")]
    filename = report.generate_json(findings, program_info, ["anti_vm", "packer"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert data["summary"]["by_category"]["packer"]["total"] == 0
    assert data["summary"]["by_category"]["packer"]["mitre"] == []


def test_generate_json_combo_only_counted_separately(program_info, now):
    """In the json report, combo_only findings should be counted under by_type.combo_only."""
    findings = [
        make_finding(type_of_technique="imports", combo_only=True),
        make_finding(type_of_technique="imports", combo_only=False),
    ]
    filename = report.generate_json(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    by_type = data["summary"]["by_category"]["anti_vm"]["by_type"]
    assert by_type["imports"] == 1
    assert by_type["combo_only"] == 1


def test_generate_json_mitre_excludes_combo_only(program_info, now):
    """In the json report, a combo_only finding's mitre tag should not appear
    in by_category.mitre unless a non-combo_only finding also carries it."""
    findings = [
        make_finding(mitre="T1547.001", combo_only=True),
        make_finding(mitre="T1543.003", combo_only=False),
    ]
    filename = report.generate_json(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    mitre = data["summary"]["by_category"]["anti_vm"]["mitre"]
    assert "T1547.001" not in mitre
    assert "T1543.003" in mitre


def test_generate_json_findings_serialized(program_info, now):
    """In the json report, the findings list should contain the serialized Finding objects (via to_dict)."""
    findings = [make_finding(name="MyAPI")]
    filename = report.generate_json(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert len(data["findings"]) == 1
    assert data["findings"][0]["name"] == "MyAPI"


def test_generate_json_meta_fields(program_info, now):
    """In the json report, meta should include tool, version, signatures_version and generated_at."""
    filename = report.generate_json([], program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert data["meta"]["generated_at"] == now.isoformat()
    assert "tool" in data["meta"]
    assert "version" in data["meta"]
    assert "signatures_version" in data["meta"]


def test_generate_json_contains_risk_score(program_info, now):
    """In the json report, summary should contain risk_score."""
    findings = [make_finding(severity="HIGH")]

    filename = report.generate_json(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        data = json.load(f)

    assert "risk_score" in data["summary"]
    assert "level" in data["summary"]["risk_score"]


# -------------------------------------------------------------------
# generate_report (txt)
# -------------------------------------------------------------------


def test_generate_report_contains_category_section(program_info, now):
    """The txt report should contain a CATEGORY header for each requested category."""
    findings = [make_finding(category="anti_vm")]
    filename = report.generate_report(
        findings, program_info, ["anti_vm", "anti_debug"], now
    )

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "CATEGORY : ANTI_VM" in output
    assert "CATEGORY : ANTI_DEBUG" in output


def test_generate_report_no_findings_message(program_info, now):
    """A category with no findings should show the 'No findings detected.' message."""
    filename = report.generate_report([], program_info, ["packer"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "No findings detected." in output


def test_generate_report_contains_type_section(program_info, now):
    """The txt report should contain a TYPE header for each detection type present."""
    findings = [
        make_finding(type_of_technique="imports"),
        make_finding(type_of_technique="strings"),
    ]
    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "TYPE : imports" in output
    assert "TYPE : strings" in output


def test_generate_report_contains_severity_section(program_info, now):
    """The txt report should contain a severity header for each severity level present."""
    findings = [
        make_finding(severity="CRITICAL"),
        make_finding(severity="LOW"),
    ]
    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "[ CRITICAL ]" in output
    assert "[ LOW ]" in output


def test_generate_report_combo_only_section_present(program_info, now):
    """The txt report should include the 'Weak standalone indicators' section for combo_only findings."""
    findings = [make_finding(combo_only=True)]
    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "-- Weak standalone indicators --" in output


def test_generate_report_no_combo_only_section_when_absent(program_info, now):
    """The txt report should not include the combo_only section when there are no combo_only findings."""
    findings = [make_finding(combo_only=False)]
    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "-- Weak standalone indicators --" not in output


def test_generate_report_header_summary_counts(program_info, now):
    """The header summary line should reflect the correct per-category finding counts."""
    findings = [
        make_finding(category="anti_vm", type_of_technique="imports"),
        make_finding(category="anti_vm", type_of_technique="strings"),
    ]
    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "Total findings : 2" in output
    assert "anti_vm" in output


def test_generate_report_mitre_excludes_combo_only(program_info, now):
    """The header MITRE summary line should not list a mitre tag that only
    appears on combo_only (unconfirmed) findings."""
    findings = [
        make_finding(mitre="T1547.001", combo_only=True),
        make_finding(mitre="T1543.003", combo_only=False),
    ]
    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "T1547.001" not in output
    assert "T1543.003" in output


def test_generate_report_displays_risk_score(program_info, now):
    """The txt report should contain the risk_score."""
    findings = [make_finding(severity="HIGH")]

    filename = report.generate_report(findings, program_info, ["anti_vm"], now)

    with open(filename, encoding="utf-8") as f:
        output = f.read()

    assert "RISK SCORE" in output


# -------------------------------------------------------------------
# --- generate_yara ---
# -------------------------------------------------------------------


def test_generate_yara_returns_none_when_no_candidates(program_info, now):
    """generate_yara() should return None when no eligible findings exist."""
    findings = [make_finding(type_of_technique="imports")]
    result = report.generate_yara(findings, program_info, now)
    assert result is None


def test_generate_yara_filters_low_severity(program_info, now):
    """generate_yara() should exclude LOW severity findings."""
    findings = [make_finding(type_of_technique="strings", severity="LOW")]
    result = report.generate_yara(findings, program_info, now)
    assert result is None


def test_generate_yara_filters_combo_only(program_info, now):
    """generate_yara() should exclude combo_only findings."""
    findings = [
        make_finding(type_of_technique="strings", severity="HIGH", combo_only=True)
    ]
    result = report.generate_yara(findings, program_info, now)
    assert result is None


def test_generate_yara_filters_imports_and_combinations(program_info, now):
    """generate_yara() should exclude imports and combinations type findings."""
    findings = [
        make_finding(type_of_technique="imports", severity="HIGH"),
        make_finding(type_of_technique="combinations", severity="CRITICAL"),
    ]
    result = report.generate_yara(findings, program_info, now)
    assert result is None


def test_generate_yara_returns_filename(program_info, now):
    """generate_yara() should return a path to a .yar file when candidates exist."""
    findings = [make_finding(type_of_technique="strings", severity="HIGH")]
    filename = report.generate_yara(findings, program_info, now)
    assert filename is not None
    assert filename.endswith(".yar")


def test_generate_yara_file_written(program_info, now):
    """generate_yara() should write the .yar file to disk."""
    findings = [make_finding(type_of_technique="strings", severity="HIGH")]
    filename = report.generate_yara(findings, program_info, now)
    assert os.path.exists(filename)


def test_generate_yara_rule_contains_category(program_info, now):
    """The generated rule name should contain the finding category."""
    findings = [
        make_finding(category="anti_vm", type_of_technique="strings", severity="HIGH")
    ]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert "GhidraMAT_anti_vm" in content


def test_generate_yara_strings_type(program_info, now):
    """Strings findings should produce a quoted string entry with nocase."""
    findings = [
        make_finding(
            type_of_technique="strings",
            name="VMware",
            severity="HIGH",
        )
    ]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert '"VMware" nocase' in content


def test_generate_yara_byte_patterns_type(program_info, now):
    """Byte pattern findings should produce a hex pattern entry."""
    findings = [
        make_finding(
            type_of_technique="byte_patterns",
            name="rdtsc",
            severity="HIGH",
            pattern="0F 31",
        )
    ]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert "{ 0F 31 }" in content


def test_generate_yara_string_patterns_type(program_info, now):
    """String pattern findings should produce a regex entry."""
    findings = [
        make_finding(
            type_of_technique="string_patterns",
            name="hardcoded_url",
            severity="HIGH",
            pattern=r"https?://[^\s]{4,}",
        )
    ]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert r"/https?://[^\s]{4,}/" in content


def test_generate_yara_multiple_categories(program_info, now):
    """Multiple categories should produce multiple rules in the same file."""
    findings = [
        make_finding(category="anti_vm", type_of_technique="strings", severity="HIGH"),
        make_finding(
            category="anti_debug", type_of_technique="strings", severity="HIGH"
        ),
    ]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert "GhidraMAT_anti_vm" in content
    assert "GhidraMAT_anti_debug" in content


def test_generate_yara_meta_fields(program_info, now):
    """The generated rule should contain expected meta fields."""
    findings = [
        make_finding(
            type_of_technique="strings",
            severity="HIGH",
            mitre="T1497.001",
        )
    ]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert "tool" in content
    assert "version" in content
    assert "category" in content
    assert "sample" in content
    assert "T1497.001" in content


def test_generate_yara_condition_capped_at_candidates(program_info, now):
    """Condition threshold should be capped at the number of candidates."""
    findings = [make_finding(type_of_technique="strings", severity="HIGH")]
    filename = report.generate_yara(findings, program_info, now)
    with open(filename, encoding="utf-8") as f:
        content = f.read()
    assert "1 of them" in content
