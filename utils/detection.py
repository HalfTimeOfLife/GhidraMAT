import re
import os


from core.finding import Finding
from utils.pattern import scan_byte_pattern
from utils.utils import (
    get_imports,
    get_strings,
    get_section_names,
    load_signatures,
    resolve_function_context,
)
from utils.xrefs import get_xrefs_to_string, get_xrefs_to_symbol

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIG_PATH = os.path.join(PROJECT_ROOT, "signatures")


def analyze(context, category):
    """Run all signature-based detections for a given category.

    Loads the signature file for the given category and matches it against
    the binary using six detection methods: imported symbols, defined
    strings, section names, string patterns, byte patterns, and import
    combinations.

    A Finding is created for each match. Combination findings are only
    produced when all required imports are present simultaneously.

    Args:
        context (Context): Analysis context of the target program.
        category (str): Name of the category to analyze, used to locate
            the corresponding signature file in signatures/.

    Returns:
        list[Finding]: All findings detected across the four detection methods.
    """
    findings = []
    signatures = load_signatures(SIG_PATH, category)
    imports = get_imports(context)
    strings = get_strings(context)
    section_names = get_section_names(context)

    if context.monitor:
        context.monitor.setMessage(f"[GhidraMAT] Searching for {category} ...")

    for api_name, data in signatures["imports"].items():
        if api_name in imports:
            xrefs = get_xrefs_to_symbol(context, api_name)
            xref_labels = [
                resolve_function_context(context.func_manager, addr) for addr in xrefs
            ]
            findings.append(
                Finding(
                    category=category,
                    type_of_technique="imports",
                    name=api_name,
                    severity=data["severity"],
                    description=data["description"],
                    combo_only=data.get("combo_only", False),
                    xrefs=xrefs,
                    xref_labels=xref_labels,
                    mitre=data.get("mitre"),
                )
            )

    for string_val, data in signatures["strings"].items():
        if string_val in strings:
            xrefs = get_xrefs_to_string(context, string_val)
            xref_labels = [
                resolve_function_context(context.func_manager, addr) for addr in xrefs
            ]
            findings.append(
                Finding(
                    category=category,
                    type_of_technique="strings",
                    name=string_val,
                    severity=data["severity"],
                    description=data["description"],
                    xrefs=xrefs,
                    xref_labels=xref_labels,
                    mitre=data.get("mitre"),
                )
            )

    for section_name, data in signatures["section_names"].items():
        if section_name in section_names:
            findings.append(
                Finding(
                    category=category,
                    type_of_technique="section_names",
                    name=section_name,
                    severity=data["severity"],
                    description=data["description"],
                    xrefs=[],
                    xref_labels=[],
                    mitre=data.get("mitre"),
                )
            )

    for sig_name, data in signatures["string_patterns"].items():
        pattern = re.compile(data["pattern"])
        matched_values = [s for s in strings if pattern.search(s)]
        if matched_values:
            findings.append(
                Finding(
                    category=category,
                    type_of_technique="string_patterns",
                    name=sig_name,
                    severity=data["severity"],
                    description=data["description"],
                    xrefs=[],
                    xref_labels=matched_values,
                    mitre=data.get("mitre"),
                    pattern=data["pattern"],
                )
            )

    # All occurrences of the same byte pattern are grouped into a single Finding.
    for sig_name, data in signatures["byte_patterns"].items():
        matches = scan_byte_pattern(context, data["pattern"])
        if matches:
            xref_labels = [
                resolve_function_context(context.func_manager, addr) for addr in matches
            ]
            findings.append(
                Finding(
                    category=category,
                    type_of_technique="byte_patterns",
                    name=sig_name,
                    severity=data["severity"],
                    description=data["description"],
                    xrefs=matches,
                    xref_labels=xref_labels,
                    mitre=data.get("mitre"),
                    pattern=data["pattern"],
                )
            )

    for combo in signatures["combinations"]:
        if set(combo["requires"]).issubset(imports):
            findings.append(
                Finding(
                    category=category,
                    type_of_technique="combinations",
                    name=combo["name"],
                    severity=combo["severity"],
                    description=combo["description"],
                    mitre=combo.get("mitre"),
                    requirements=combo["requires"],
                )
            )

    return findings
