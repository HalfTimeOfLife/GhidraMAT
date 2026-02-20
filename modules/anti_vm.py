# This module provides functionality for detecting and analyzing anti-virtual machine (anti-VM) or anti-emulation techniques.

# @author HalfTimeOfLife
# @category GhidraMAT.modules

import json
import os

from core.finding import Finding
from utils.utils import get_imports, load_signatures, get_strings

# Chemin absolu vers signatures.json
SIG_PATH = os.path.join(os.path.dirname(__file__), "../signatures/signatures.json")
CATEGORY = "anti_vm"

def analyze(context):
    findings = []
    anti_vm_signatures = load_signatures(SIG_PATH, CATEGORY)
    imports = get_imports(context)
    strings = get_strings(context)
    
    # imports    
    for api_name, data in anti_vm_signatures["imports"].items():
        if api_name in imports:
            is_combo_only = data.get("combo_only", False)
            findings.append(Finding(
                category=CATEGORY,
                type_of_technique="imports",
                name=api_name,
                severity=data["severity"],
                address=imports[api_name],
                description=data["description"],
                combo_only=is_combo_only
            ))
    
    # strings      
    for string_val, data in anti_vm_signatures["strings"].items():
        if string_val in strings:
            findings.append(Finding(
                category=CATEGORY,
                type_of_technique="strings",
                name=string_val,
                severity=data["severity"],
                address=None,
                description=data["description"]
            ))

    # combinations
    for combo in anti_vm_signatures["combinations"]:
        if set(combo["requires"]).issubset(imports):
            findings.append(Finding(
                category=CATEGORY,
                type_of_technique="combinations",
                name=combo["name"],
                severity=combo["severity"],
                address=None,
                description=combo["description"]
            ))
    
    return findings