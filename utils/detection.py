import os

from core.finding import Finding
from utils.utils import get_imports, load_signatures, get_strings, resolve_function_context
from utils.xrefs import get_xrefs_to_symbol, get_xrefs_to_string
from utils.pattern import scan_byte_pattern


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIG_PATH = os.path.join(PROJECT_ROOT, "signatures")

def analyze(context, category):
    """Run all signature-based detections for a given category.

    Loads the signature file for the given category and matches it against
    the binary using four detection methods in order: imported symbols,
    defined strings, byte patterns, and import combinations.

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
    
    if context.monitor:
        context.monitor.setMessage("[GhidraMAT] Searching for {} ...".format(category))
        


    for api_name, data in signatures["imports"].items():
        if api_name in imports:
            xrefs = get_xrefs_to_symbol(context, api_name)
            xref_labels = [resolve_function_context(context.func_manager, addr) for addr in xrefs]
            findings.append(Finding(
                category=category,
                type_of_technique="imports",
                name=api_name,
                severity=data["severity"],
                address=imports[api_name],
                description=data["description"],
                combo_only=data.get("combo_only", False),
                xrefs=xrefs,
                xref_labels=xref_labels,
                mitre=data["mitre"]
            ))

    for string_val, data in signatures["strings"].items():
        if string_val in strings:
            xrefs = get_xrefs_to_string(context, string_val)
            xref_labels = [resolve_function_context(context.func_manager, addr) for addr in xrefs]
            findings.append(Finding(
                category=category,
                type_of_technique="strings",
                name=string_val,
                severity=data["severity"],
                address=None,
                description=data["description"],
                xrefs=xrefs,
                xref_labels=xref_labels,
                mitre=data["mitre"]
            ))

    # All occurrences of the same byte pattern are grouped into a single Finding.
    for sig_name, data in signatures["byte_patterns"].items():
        matches = scan_byte_pattern(context, data["pattern"])
        if matches:
            xref_labels = [resolve_function_context(context.func_manager, addr) for addr in matches]
            findings.append(Finding(
                category=category,
                type_of_technique="byte_patterns",
                name=sig_name,
                severity=data["severity"],
                address=None,
                description=data["description"],
                xrefs=matches,
                xref_labels=xref_labels,
                mitre=data["mitre"]
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
                mitre=combo["mitre"],
                requirements=combo["requires"]
            ))

    return findings