from core.finding import Finding, MAX_DISPLAY


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

# -------------------------------------------------------------------
# --- to_dict ---
# -------------------------------------------------------------------

def test_to_dict_keys_present():
    """to_dict should return a dict with exactly the expected set of keys."""
    f = make_finding()
    result = f.to_dict()
    
    expected_keys = {"category", "type", "name", "severity", "mitre", "description", "combo_only", "xref_labels", "requirements"}
    assert set(result.keys()) == expected_keys

def test_to_dict_values_correct():
    """to_dict should map constructor arguments to their correct dict values."""
    f = make_finding()
    result = f.to_dict()

    assert result["category"] == "anti_vm"
    assert result["type"] == "imports"
    assert result["name"] == "TestAPI"
    assert result["severity"] == "HIGH"
    assert result["description"] == "Test description"

def test_to_dict_mitre_none():
    """to_dict should return None for mitre when not provided."""
    f = make_finding()
    result = f.to_dict()
    
    assert result["mitre"] is None

def test_to_dict_mitre_not_string():
    """to_dict should return None for mitre when a non-string value is passed."""
    f = make_finding(mitre=123)
    result = f.to_dict()
    
    assert result["mitre"] is None


def test_to_dict_requirements_none():
    """to_dict should return None for requirements when not provided."""
    f = make_finding()
    result = f.to_dict()
    
    assert result["requirements"] is None

def test_to_dict_combo_only_true():
    """to_dict should preserve combo_only=True as a boolean."""
    f = make_finding(combo_only=True)
    result = f.to_dict()
    
    assert result["combo_only"] is True

def test_to_dict_xref_labels():
    """to_dict should return xref_labels as-is from the constructor."""
    labels = ["0x1000 (main)", "0x2000 (test+0x10)"]
    f = make_finding(xref_labels=labels)
    result = f.to_dict()
    
    assert result["xref_labels"] == labels

# -------------------------------------------------------------------
# --- __str__ ---
# -------------------------------------------------------------------

def test_str_basic():
    """__str__ should include the finding name, severity, category and description."""
    f = make_finding()
    result = f.__str__()
    
    assert "TestAPI" in result
    assert "HIGH" in result
    assert "anti_vm" in result
    assert "Test description" in result

def test_str_combo_only_note_present():
    """__str__ should include the standalone indicator warning when combo_only is True."""
    f = make_finding(combo_only=True)
    note = "\n   [!] Standalone indicator weak -- meaningful only in combination"
    result = f.__str__()
    
    assert note in result

def test_str_no_combo_only_note_absent():
    """__str__ should not include the standalone indicator warning when combo_only is False."""
    f = make_finding(combo_only=False)
    note = "\n   [!] Standalone indicator weak -- meaningful only in combination"
    result = f.__str__()
    
    assert note not in result

def test_str_with_requirements():
    """__str__ should include a 'Requires' line when requirements are set."""
    requirements=["TestAPI1", "TestAPI2"]
    f = make_finding(requirements=requirements)
    result = f.__str__()
    
    assert "Requires" in result
    assert "TestAPI1" in result
    assert "TestAPI2" in result

def test_str_empty_xrefs():
    """__str__ should not include a xrefs section when xref_labels is empty."""
    f = make_finding(xref_labels=[])
    result = f.__str__()
    
    assert "Called from" not in result
    assert "Occurrences" not in result

def test_str_xrefs_imports_called_from():
    """__str__ should label the xrefs section 'Called from' for imports findings."""
    xref_labels = ["0x1000 (main)", "0x2000 (test+0x10)", "0x3000 (init)"]
    f = make_finding(type_of_technique="imports", xref_labels=xref_labels)
    result = f.__str__()

    assert "Called from" in result
    assert "main" in result
    assert "test" in result
    assert "init" in result

def test_str_xrefs_byte_patterns_occurrences():
    """__str__ should label the xrefs section 'Occurrences' for byte_patterns findings."""
    xref_labels = ["0x1000 (main)", "0x2000 (test+0x10)", "0x3000 (init)"]
    f = make_finding(type_of_technique="byte_patterns", xref_labels=xref_labels)
    result = f.__str__()

    assert "Occurrences" in result
    assert "main" in result
    assert "test" in result
    assert "init" in result


def test_str_xrefs_deduplication_same_function():
    """__str__ should group multiple xrefs from the same function as 'func (Nx)'."""
    xref_labels=["0x1000 (main)", "0x1010 (main+0x10)"]
    f = make_finding(xref_labels=xref_labels)
    result = f.__str__()
    
    assert "main (2x)" in result

def test_str_xrefs_max_display_not_exceeded():
    """__str__ should display at most MAX_DISPLAY distinct functions in the xrefs section."""
    xref_labels = [
    "0x1000 (func_1)",
    "0x1010 (func_2)",
    "0x1020 (func_3)",
    "0x1030 (func_4)",
    "0x1040 (func_5)",
    "0x1050 (func_6)",
    "0x1060 (func_7)",
    "0x1070 (func_8)",
]
    f = make_finding(xref_labels=xref_labels)
    result = f.__str__()
    
    assert result.count("func_") <= MAX_DISPLAY  

def test_str_xrefs_overflow_shows_more():
    """__str__ should append '... and N more functions' when xrefs exceed MAX_DISPLAY."""
    xref_labels = [
    "0x1000 (func_1)",
    "0x1010 (func_2)",
    "0x1020 (func_3)",
    "0x1030 (func_4)",
    "0x1040 (func_5)",
    "0x1050 (func_6)",
    "0x1060 (func_7)",
    "0x1070 (func_8)",
]
    f = make_finding(xref_labels=xref_labels)
    result = f.__str__()
    
    assert "and 2 more" in result