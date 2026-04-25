# This module provides the generic detection logic for all GhidraMAT categories.
# It loads signatures from the directory signatures/ and matches imports, strings,
# byte patterns and combinations against the analyzed binary.
# @author HalfTimeOfLife
# @category GhidraMAT.utils

from core.finding import Finding
from utils.utils import get_imports, load_signatures, get_strings
from utils.xrefs import get_xrefs_to_symbol, get_xrefs_to_string
from utils.pattern import scan_byte_pattern
import os
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIG_PATH = os.path.join(PROJECT_ROOT, "signatures")

def analyze(context, category):
    findings = []
    signatures = load_signatures(SIG_PATH, category)
    imports = get_imports(context)
    strings = get_strings(context)
    
    if context.monitor:
        context.monitor.setMessage("[GhidraMAT] Searching for {} ...".format(category))
        


    for api_name, data in signatures["imports"].items():
        if api_name in imports:
            xrefs = get_xrefs_to_symbol(context, api_name)
            findings.append(Finding(
                category=category,
                type_of_technique="imports",
                name=api_name,
                severity=data["severity"],
                address=imports[api_name],
                description=data["description"],
                combo_only=data.get("combo_only", False),
                xrefs=xrefs
            ))

    for string_val, data in signatures["strings"].items():
        if string_val in strings:
            xrefs = get_xrefs_to_string(context, string_val)
            findings.append(Finding(
                category=category,
                type_of_technique="strings",
                name=string_val,
                severity=data["severity"],
                address=None,
                description=data["description"],
                xrefs=xrefs
            ))

    for sig_name, data in signatures["byte_patterns"].items():
        for addr in scan_byte_pattern(context, data["pattern"]):
            findings.append(Finding(
                category=category,
                type_of_technique="byte_patterns",
                name=sig_name,
                severity=data["severity"],
                address=addr,
                description=data["description"]
            ))

    for combo in signatures["combinations"]:
        if set(combo["requires"]).issubset(imports):
            findings.append(Finding(
                category=category,
                type_of_technique="combinations",
                name=combo["name"],
                severity=combo["severity"],
                address=None,
                description=combo["description"],
                requirements=combo["requires"]
            ))

    return findings