"""tests/test_scoring.py

Tests for core.scoring.compute_risk_score
"""

from core.finding import Finding
from core.scoring import compute_risk_score

# -------------------------------------------------------------------
# --- helpers ---
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


def make_config(*rules):
    """Build a minimal scoring config from (level, min_counts) tuples.

    Example: make_config(("CRITICAL", {"CRITICAL": 1}), ("HIGH", {"HIGH": 3}))
    """
    return {
        "rules": [
            {"level": level, "min_counts": min_counts} for level, min_counts in rules
        ]
    }


STANDARD_CONFIG = make_config(
    ("CRITICAL", {"CRITICAL": 1}),
    ("HIGH", {"HIGH": 3}),
    ("MEDIUM", {"HIGH": 1}),
    ("MEDIUM", {"MEDIUM": 3}),
    ("LOW", {"MEDIUM": 1}),
    ("LOW", {"LOW": 1}),
)

# -------------------------------------------------------------------
# --- return structure ---
# -------------------------------------------------------------------


def test_return_has_level_key():
    """compute_risk_score() should always return a dict with a 'level' key."""
    result = compute_risk_score([], config=make_config())
    assert "level" in result


def test_return_has_counts_key():
    """compute_risk_score() should always return a dict with a 'counts' key."""
    result = compute_risk_score([], config=make_config())
    assert "counts" in result


def test_counts_contains_all_severities():
    """counts should always contain exactly the four severity keys."""
    result = compute_risk_score([], config=make_config())
    assert set(result["counts"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# -------------------------------------------------------------------
# --- CLEAN ---
# -------------------------------------------------------------------


def test_clean_when_no_findings():
    """No findings at all should produce level CLEAN."""
    result = compute_risk_score([], config=STANDARD_CONFIG)
    assert result["level"] == "CLEAN"


def test_clean_counts_all_zero():
    """CLEAN result should have all counts at zero."""
    result = compute_risk_score([], config=STANDARD_CONFIG)
    assert all(v == 0 for v in result["counts"].values())


def test_clean_when_only_combo_only_findings():
    """Only combo_only findings (excluded from scoring) should still yield CLEAN."""
    findings = [
        make_finding(severity="HIGH", combo_only=True),
        make_finding(severity="CRITICAL", combo_only=True),
    ]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "CLEAN"


# -------------------------------------------------------------------
# --- CRITICAL ---
# -------------------------------------------------------------------


def test_critical_on_one_critical_finding():
    """A single CRITICAL finding should yield level CRITICAL."""
    findings = [make_finding(severity="CRITICAL")]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "CRITICAL"


def test_critical_counts_incremented():
    """CRITICAL count should reflect the number of CRITICAL findings."""
    findings = [
        make_finding(severity="CRITICAL"),
        make_finding(severity="CRITICAL"),
    ]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["counts"]["CRITICAL"] == 2


def test_critical_takes_priority_over_high():
    """CRITICAL rule should fire before HIGH rule when both thresholds are met."""
    findings = [
        make_finding(severity="CRITICAL"),
        make_finding(severity="HIGH"),
        make_finding(severity="HIGH"),
        make_finding(severity="HIGH"),
    ]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "CRITICAL"


# -------------------------------------------------------------------
# --- HIGH ---
# -------------------------------------------------------------------


def test_high_on_three_high_findings():
    """Three HIGH findings (and no CRITICAL) should yield level HIGH."""
    findings = [make_finding(severity="HIGH") for _ in range(3)]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "HIGH"


def test_not_high_on_two_high_findings():
    """Two HIGH findings should not reach the HIGH threshold (requires 3)."""
    findings = [make_finding(severity="HIGH") for _ in range(2)]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] != "HIGH"


# -------------------------------------------------------------------
# --- MEDIUM ---
# -------------------------------------------------------------------


def test_medium_on_one_high_finding():
    """One HIGH finding (below the HIGH threshold) should yield MEDIUM."""
    findings = [make_finding(severity="HIGH")]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "MEDIUM"


def test_medium_on_three_medium_findings():
    """Three MEDIUM findings with no HIGH should yield MEDIUM."""
    findings = [make_finding(severity="MEDIUM") for _ in range(3)]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "MEDIUM"


# -------------------------------------------------------------------
# --- LOW ---
# -------------------------------------------------------------------


def test_low_on_one_medium_finding():
    """One MEDIUM finding (below the MEDIUM threshold) should yield LOW."""
    findings = [make_finding(severity="MEDIUM")]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "LOW"


def test_low_on_only_low_findings():
    """Only LOW findings should yield level LOW."""
    findings = [make_finding(severity="LOW") for _ in range(5)]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["level"] == "LOW"


# -------------------------------------------------------------------
# --- combo_only exclusion ---
# -------------------------------------------------------------------


def test_combo_only_excluded_from_counts():
    """combo_only findings should not be counted toward any severity bucket."""
    findings = [
        make_finding(severity="HIGH", combo_only=True),
        make_finding(severity="HIGH", combo_only=False),
    ]
    result = compute_risk_score(findings, config=STANDARD_CONFIG)
    assert result["counts"]["HIGH"] == 1


def test_combo_only_does_not_affect_level():
    """Adding combo_only findings should not change the risk level."""
    base = [make_finding(severity="LOW")]
    with_combo = base + [
        make_finding(severity="CRITICAL", combo_only=True),
        make_finding(severity="HIGH", combo_only=True),
        make_finding(severity="HIGH", combo_only=True),
        make_finding(severity="HIGH", combo_only=True),
    ]
    assert (
        compute_risk_score(base, config=STANDARD_CONFIG)["level"]
        == compute_risk_score(with_combo, config=STANDARD_CONFIG)["level"]
    )


# -------------------------------------------------------------------
# --- first-rule-wins ordering ---
# -------------------------------------------------------------------


def test_first_matching_rule_wins():
    """The first rule whose thresholds are satisfied should determine the level."""
    config = make_config(
        ("MEDIUM", {"HIGH": 1}),
        ("LOW", {"HIGH": 1}),
    )
    findings = [make_finding(severity="HIGH")]
    result = compute_risk_score(findings, config=config)
    assert result["level"] == "MEDIUM"


def test_rule_order_matters():
    """Swapping rule order should change the outcome when both rules match."""
    findings = [make_finding(severity="HIGH")]

    config_medium_first = make_config(
        ("MEDIUM", {"HIGH": 1}),
        ("LOW", {"HIGH": 1}),
    )
    config_low_first = make_config(
        ("LOW", {"HIGH": 1}),
        ("MEDIUM", {"HIGH": 1}),
    )

    assert compute_risk_score(findings, config=config_medium_first)["level"] == "MEDIUM"
    assert compute_risk_score(findings, config=config_low_first)["level"] == "LOW"


# -------------------------------------------------------------------
# --- multi-severity thresholds ---
# -------------------------------------------------------------------


def test_multi_condition_rule_requires_all_thresholds():
    """A rule with multiple min_counts entries should only fire when ALL are met."""
    config = make_config(
        ("CRITICAL", {"HIGH": 2, "MEDIUM": 2}),
    )

    # Only HIGH threshold met
    only_high = [make_finding(severity="HIGH") for _ in range(2)]
    assert compute_risk_score(only_high, config=config)["level"] != "CRITICAL"

    # Both thresholds met
    both = only_high + [make_finding(severity="MEDIUM") for _ in range(2)]
    assert compute_risk_score(both, config=config)["level"] == "CRITICAL"


# -------------------------------------------------------------------
# --- fallback ---
# -------------------------------------------------------------------


def test_fallback_when_no_rule_matches():
    """When findings exist but no rule matches, the level should fall back to LOW."""
    config = make_config(
        ("CRITICAL", {"CRITICAL": 999}),
    )
    findings = [make_finding(severity="HIGH")]
    result = compute_risk_score(findings, config=config)
    assert result["level"] == "LOW"


def test_no_fallback_when_no_findings_and_no_rule_matches():
    """When there are no findings AND no rule matches, the level should still be CLEAN."""
    config = make_config()
    result = compute_risk_score([], config=config)
    assert result["level"] == "CLEAN"
