"""Validate all GhidraMAT signature JSON files.

Checks that every file in signatures/ is well-formed JSON and that
each entry respects the expected schema. Exits with code 1 on any error.
"""

import json
import os
import sys

SIGNATURES_DIR = os.path.join(os.path.dirname(__file__), "..", "signatures")

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

REQUIRED_TOP_LEVEL = {"imports", "strings", "byte_patterns", "combinations"}

errors = []

def err(filepath, msg):
    errors.append(f"[{os.path.basename(filepath)}] {msg}")
    
def validate_import(filepath, api_name, data):
    if not isinstance(data, dict):
        err(filepath, f"imports.{api_name}: expected object, got {type(data).__name__}")
        return
    if "severity" not in data:
        err(filepath, f"imports.{api_name}: missing required field 'severity'")
    elif data["severity"] not in VALID_SEVERITIES:
        err(filepath, f"imports.{api_name}: invalid severity '{data['severity']}'")
    if "description" not in data:
        err(filepath, f"imports.{api_name}: missing required field 'description'")
    if "combo_only" in data and not isinstance(data["combo_only"], bool):
        err(filepath, f"imports.{api_name}: 'combo_only' must be a boolean")
    
def validate_string(filepath, string_val, data):
    if not isinstance(data, dict):
        err(filepath, f"strings.{string_val!r}: expected object, got {type(data).__name__}")
        return
    if "severity" not in data:
        err(filepath, f"strings.{string_val!r}: missing required field 'severity'")
    elif data["severity"] not in VALID_SEVERITIES:
        err(filepath, f"strings.{string_val!r}: invalid severity '{data['severity']}'")
    if "description" not in data:
        err(filepath, f"strings.{string_val!r}: missing required field 'description'")

def validate_byte_pattern(filepath, sig_name, data):
    if not isinstance(data, dict):
        err(filepath, f"byte_patterns.{sig_name}: expected object, got {type(data).__name__}")
        return
    if "pattern" not in data:
        err(filepath, f"byte_patterns.{sig_name}: missing required field 'pattern'")
    else:
        for byte in data["pattern"].split():
            if byte != "??" and not all(c in "0123456789abcdefABCDEF" for c in byte):
                err(filepath, f"byte_patterns.{sig_name}: invalid byte token '{byte}' in pattern")
    if "severity" not in data:
        err(filepath, f"byte_patterns.{sig_name}: missing required field 'severity'")
    elif data["severity"] not in VALID_SEVERITIES:
        err(filepath, f"byte_patterns.{sig_name}: invalid severity '{data['severity']}'")
    if "description" not in data:
        err(filepath, f"byte_patterns.{sig_name}: missing required field 'description'")

def validate_combination(filepath, i, combo):
    if not isinstance(combo, dict):
        err(filepath, f"combinations[{i}]: expected object, got {type(combo).__name__}")
        return
    for field in ("name", "requires", "severity", "description"):
        if field not in combo:
            err(filepath, f"combinations[{i}]: missing required field '{field}'")
    if "requires" in combo and not isinstance(combo["requires"], list):
        err(filepath, f"combinations[{i}]: 'requires' must be a list")
    if "severity" in combo and combo["severity"] not in VALID_SEVERITIES:
        err(filepath, f"combinations[{i}]: invalid severity '{combo['severity']}'")
    
def validate_file(filepath):
    with open(filepath, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            err(filepath, f"invalid JSON: {e}")
            return
    
    missing = REQUIRED_TOP_LEVEL - data.keys()
    if missing:
        err(filepath, f"missing detection types (top-level keys): {missing}")
    

    for api_name, entry in data.get("imports", {}).items():
        validate_import(filepath, api_name, entry)

    for string_val, entry in data.get("strings", {}).items():
        validate_string(filepath, string_val, entry)

    for sig_name, entry in data.get("byte_patterns", {}).items():
        validate_byte_pattern(filepath, sig_name, entry)

    for i, combo in enumerate(data.get("combinations", [])):
        validate_combination(filepath, i, combo)
    
def main():
    sig_files = [
        os.path.join(SIGNATURES_DIR, f) 
        for f in os.listdir(SIGNATURES_DIR) 
        if f.endswith(".json")
    ]
    
    if not sig_files:
        print("No signatures files found ...")
        sys.exit(1)
        
    for filepath in sorted(sig_files):
        validate_file(filepath)
        
    if errors:
        print(f"Validation failed — {len(errors)} error(s):\n")
        for e in errors:
            print(f"  {e}")
        sys.exit(1)

    print(f"All {len(sig_files)} signature file(s) are valid.")
    
if __name__ == "__main__":
    main()