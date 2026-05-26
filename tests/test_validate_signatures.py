import json
import pytest

from scripts.validate_signatures import validate_file, errors


# -------------------------------------------------------------------
# Common fixtures / helpers
# -------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clear_errors():
    """Clear the global errors list before each test."""
    errors.clear()


def minimal_valid_json():
    """Return a minimal JSON structure that matches the expected schema."""
    return {
        "sig_version": 1,
        "imports": {},
        "strings": {},
        "byte_patterns": {},
        "combinations": []
    }
    
def build_import(severity="HIGH", description="Test description", combo_only=None):
    entry = {}

    if severity is not None:
        entry["severity"] = severity

    if description is not None:
        entry["description"] = description

    if combo_only is not None:
        entry["combo_only"] = combo_only

    return entry

def build_string(severity="HIGH", description="Test description"):
    entry = {}

    if severity is not None:
        entry["severity"] = severity

    if description is not None:
        entry["description"] = description

    return entry

def build_byte_pattern(pattern="0F A2", severity="HIGH", description="Test description"):
    entry = {}

    if pattern is not None:
        entry["pattern"] = pattern

    if severity is not None:
        entry["severity"] = severity

    if description is not None:
        entry["description"] = description

    return entry

def build_combination(name="Test combination", requires=None, severity="HIGH", description="Test description"):
    entry = {}

    if name is not None:
        entry["name"] = name

    if requires is not None:
        entry["requires"] = requires
    else:
        entry["requires"] = ["Requirement1", "Requirement2"]

    if severity is not None:
        entry["severity"] = severity

    if description is not None:
        entry["description"] = description

    return entry

def write_json(tmp_path, data, filename="test.json"):
    """Write a JSON object to a temporary file and return its path."""
    path = tmp_path / filename
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def run_validation(tmp_path, data, filename="test.json"):
    """Write a temporary JSON file and run validate_file on it."""
    path = write_json(tmp_path, data, filename)
    validate_file(path)
    return path


def assert_no_errors():
    """Check that no validation errors were reported."""
    assert errors == []


# -------------------------------------------------------------------
# Valid file tests
# -------------------------------------------------------------------

def test_valid_empty_file(tmp_path):
    """A file with sig_version and empty detection sections should produce no errors."""
    data = minimal_valid_json()
    run_validation(tmp_path, data)
    assert_no_errors()


def test_valid_file_with_import(tmp_path):
    """A file with a well-formed import entry should produce no errors."""
    data = minimal_valid_json()
    data["imports"]["TestAPI"] = build_import()
    run_validation(tmp_path, data)
    assert_no_errors()


def test_valid_file_with_combo_only_import(tmp_path):
    """A file with a valid combo_only import (boolean True) should produce no errors."""
    data = minimal_valid_json()
    data["imports"]["TestAPI"] = build_import(
        severity="LOW",
        combo_only=True
    )
    run_validation(tmp_path, data)
    assert_no_errors()


def test_valid_file_with_string(tmp_path):
    """A file with a well-formed string entry should produce no errors."""
    data = minimal_valid_json()
    data["strings"]["Test string"] = build_string()
    run_validation(tmp_path, data)
    assert_no_errors()


def test_valid_file_with_byte_pattern(tmp_path):
    """A file with a well-formed byte_pattern entry should produce no errors."""
    data = minimal_valid_json()
    data["byte_patterns"]["Test bytes"] = build_byte_pattern()
    run_validation(tmp_path, data)
    assert_no_errors()


def test_valid_file_with_combination(tmp_path):
    """A file with a well-formed combination entry should produce no errors."""
    data = minimal_valid_json()
    data["combinations"] = [build_combination()]
    run_validation(tmp_path, data)
    assert_no_errors()


# -------------------------------------------------------------------
# Top-level schema tests
# -------------------------------------------------------------------

def test_missing_sig_version(tmp_path):
    """Missing top-level key 'sig_version' should produce an error."""
    data = minimal_valid_json()
    data.pop("sig_version", None)
    run_validation(tmp_path, data)
    assert any("sig_version" in e for e in errors)


def test_missing_imports_key(tmp_path):
    """Missing top-level key 'imports' should produce an error."""
    data = minimal_valid_json()
    data.pop("imports", None)
    run_validation(tmp_path, data)
    assert any("imports" in e for e in errors)


def test_missing_strings_key(tmp_path):
    """Missing top-level key 'strings' should produce an error."""
    data = minimal_valid_json()
    data.pop("strings", None)
    run_validation(tmp_path, data)
    assert any("strings" in e for e in errors)


def test_missing_byte_patterns_key(tmp_path):
    """Missing top-level key 'byte_patterns' should produce an error."""
    data = minimal_valid_json()
    data.pop("byte_patterns", None)
    run_validation(tmp_path, data)
    assert any("byte_patterns" in e for e in errors)


def test_missing_combinations_key(tmp_path):
    """Missing top-level key 'combinations' should produce an error."""
    data = minimal_valid_json()
    data.pop("combinations", None)
    run_validation(tmp_path, data)
    assert any("combinations" in e for e in errors)


# -------------------------------------------------------------------
# Imports validation tests
# -------------------------------------------------------------------

def test_missing_severity_in_import(tmp_path):
    """Import entry without severity should produce an error."""
    data = minimal_valid_json()
    data["imports"]["TestAPI"] = build_import(
        severity=None,
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("severity" in e for e in errors)


def test_missing_description_in_import(tmp_path):
    """Import entry without description should produce an error."""
    data = minimal_valid_json()
    data["imports"]["TestAPI"] = build_import(
        severity="HIGH",
        description=None
    )
    run_validation(tmp_path, data)
    assert any("description" in e for e in errors)


def test_combo_only_not_boolean(tmp_path):
    """Import entry with non-boolean combo_only should produce an error."""
    data = minimal_valid_json()
    data["imports"]["TestAPI"] = build_import(
        severity="HIGH",
        description="Test description",
        combo_only="True"
    )
    run_validation(tmp_path, data)
    assert any("combo_only" in e for e in errors)


def test_invalid_severity_in_import(tmp_path):
    """Import entry with invalid severity should produce an error."""
    data = minimal_valid_json()
    data["imports"]["TestAPI"] = build_import(
        severity="SeverityTest",
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("severity" in e for e in errors)


# -------------------------------------------------------------------
# Strings validation tests
# -------------------------------------------------------------------

def test_missing_severity_in_string(tmp_path):
    """String entry without severity should produce an error."""
    data = minimal_valid_json()
    data["strings"]["TestString"] = build_string(
        severity=None,
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("severity" in e for e in errors)


def test_missing_description_in_string(tmp_path):
    """String entry without description should produce an error."""
    data = minimal_valid_json()
    data["strings"]["TestString"] = build_string(
        severity="HIGH",
        description=None
    )
    run_validation(tmp_path, data)
    assert any("description" in e for e in errors)
    
def test_invalid_severity_in_strings(tmp_path):
    """String entry with invalid severity should produce an error."""
    data = minimal_valid_json()
    data["strings"]["TestString"] = build_string(
        severity="SeverityTest",
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("severity" in e for e in errors)


# -------------------------------------------------------------------
# Byte patterns validation tests
# -------------------------------------------------------------------

def test_missing_pattern_in_byte_pattern(tmp_path):
    """Byte pattern entry without pattern should produce an error."""
    data = minimal_valid_json()
    data["byte_patterns"]["TestPattern"] = build_byte_pattern(
        pattern=None,
        severity="HIGH",
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("pattern" in e for e in errors)


def test_invalid_byte_in_pattern(tmp_path):
    """Byte pattern contains invalid hex token should produce an error."""
    data = minimal_valid_json()
    data["byte_patterns"]["TestPattern"] = build_byte_pattern(
        pattern="ZZ A2",
        severity="HIGH",
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("ZZ" in e for e in errors)


def test_invalid_severity_in_byte_pattern(tmp_path):
    """Byte pattern with invalid severity should produce an error."""
    data = minimal_valid_json()
    data["byte_patterns"]["TestPattern"] = build_byte_pattern(
        pattern="0F A2",
        severity="SeverityTest",
        description="Test description"
    )
    run_validation(tmp_path, data)
    assert any("severity" in e for e in errors)


# -------------------------------------------------------------------
# Combinations validation tests
# -------------------------------------------------------------------

def test_missing_name_in_combination(tmp_path):
    """Combination entry without name should produce an error."""
    data = minimal_valid_json()
    data["combinations"].append(build_combination(
        name=None,
        requires=["Requirement1", "Requirement2", "Requirement3"],
        severity="HIGH",
        description="Test description"
    ))
    run_validation(tmp_path, data)
    assert any("name" in e for e in errors)


def test_missing_requires_in_combination(tmp_path):
    """Combination entry without requires should produce an error."""
    data = minimal_valid_json()
    data["combinations"].append(build_combination(
        name="Test Combination",
        requires=[],
        severity="HIGH",
        description="Test description"
    ))
    run_validation(tmp_path, data)
    assert any("requires" in e for e in errors)


def test_requires_not_a_list(tmp_path):
    """Combination entry where requires is not a list should produce an error."""
    data = minimal_valid_json()
    data["combinations"].append(build_combination(
        name="Test Combination",
        requires={"test1" : 1, "test2" : 3},
        severity="HIGH",
        description="Test description"
    ))
    run_validation(tmp_path, data)
    assert any("requires" in e for e in errors)


def test_invalid_severity_in_combination(tmp_path):
    """Combination entry with invalid severity should produce an error."""
    data = minimal_valid_json()
    data["combinations"].append(build_combination(
        severity="INVALID"
    ))
    run_validation(tmp_path, data)
    assert any("severity" in e for e in errors)


# -------------------------------------------------------------------
# JSON parsing tests
# -------------------------------------------------------------------

def test_invalid_json(tmp_path):
    """Malformed JSON file should produce an error and not crash."""
    path = tmp_path / "test.json"
    path.write_text("{ not valid json }", encoding="utf-8")
    validate_file(path)
    assert any("invalid JSON" in e for e in errors)