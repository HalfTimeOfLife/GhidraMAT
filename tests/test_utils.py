"""tests/test_utils.py

Tests for utils.utils.load_signatures
"""

import json

import pytest

from utils.utils import SIGNATURES_VERSION, load_signatures, load_config

# -------------------------------------------------------------------
# --- load_signatures ---
# -------------------------------------------------------------------


def test_load_signatures_valid(tmp_path):
    """load_signatures() should correctly load any correct signatures file."""
    data = {
        "sig_version": SIGNATURES_VERSION,
        "imports": {"TestAPI": {"severity": "HIGH", "description": "Test description"}},
        "strings": {},
        "byte_patterns": {},
        "combinations": [],
    }

    path = tmp_path / "test_signatures.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    result = load_signatures(str(tmp_path), "test_signatures")
    assert result == data


def test_load_signatures_version_mismatch(tmp_path):
    """load_signatures() should raise an error if the signatures version is incorrect."""
    data = {
        "sig_version": SIGNATURES_VERSION + 1,
        "imports": {"TestAPI": {"severity": "HIGH", "description": "Test description"}},
        "strings": {},
        "byte_patterns": {},
        "combinations": [],
    }
    path = tmp_path / "test_signatures.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        load_signatures(str(tmp_path), "test_signatures")


def test_load_signatures_missing_file(tmp_path):
    """load_signatures() should raise an error if the signatures file doesn't exists."""
    with pytest.raises(FileNotFoundError):
        load_signatures(str(tmp_path), "nonexistent_signatures")


# -------------------------------------------------------------------
# --- load_config ---
# -------------------------------------------------------------------


def test_load_config_valid(tmp_path):
    """load_config() should correctly load any valid JSON file."""
    data = {"generate_yara": False}
    path = tmp_path / "test_config.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    result = load_config(str(path))
    assert result == data


def test_load_config_missing_file(tmp_path):
    """load_config() should raise an error if the file doesn't exist."""
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "nonexistent.json"))


def test_load_config_invalid_json(tmp_path):
    """load_config() should raise an error if the file contains invalid JSON."""
    path = tmp_path / "bad_config.json"
    path.write_text("{ not valid json }", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        load_config(str(path))
