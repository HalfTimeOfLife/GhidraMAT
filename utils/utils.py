import json
import os

from ghidra.program.model.listing import BookmarkType
from ghidra.app.plugin.core.colorizer import ColorizingService
from java.awt import Color

# Background colors applied to findings based on their severity level.
SEVERITY_COLORS = {
    "CRITICAL": Color(220, 50,  50),
    "HIGH":     Color(220, 130, 50),
    "MEDIUM":   Color(220, 200, 50),
    "LOW":      Color(150, 200, 100)
}

BANNER = r"""
=======================================================
 _____ _     _     _            __  __       _______ 
/ ____| |   (_)   | |          |  \/  |   /\|__   __|
| |  __| |__  _  __| |_ __ __ _| \  / |  /  \  | |   
| | |_ | '_ \| |/ _` | '__/ _` | |\/| | / /\ \ | |   
| |__| | | | | | (_| | | | (_| | |  | |/ ____ \| |   
 \_____|_| |_|_|\__,_|_|  \__,_|_|  |_/_/    \_\_|               
=======================================================
"""

def print_banner():
    """ Print GhidraMAT banner for report and console."""
    print(BANNER)

def get_imports(context):
    """Retrieve imported symbols of a program.

    Iterates over external symbols in the symbol table and maps
    each symbol name to its corresponding memory address.

    Args:
        context (Context): Analysis context of the target program.

    Returns:
        dict[str, Address]: A dictionary {symbol_name: address}.
    """
    imports = {}
    for symbol in context.symbol_table.getExternalSymbols():
        imports[symbol.getName()] = symbol.getAddress()
    return imports

def get_strings(context):
    """Retrieve all defined strings from a program.

    Iterates over defined data in the program listing and collects
    entries that have a string value.

    Args:
        context (Context): Analysis context of the target program.

    Returns:
        set[str]: A set of string values found in the program's data.
    """
    strings = set()
    for s in context.listing.getDefinedData(True):
        if s.hasStringValue():
            strings.add(str(s.getValue()))
    return strings
    
def load_signatures(signatures_dir, name):
    """Load a JSON signature file from a directory.

    Args:
        signatures_dir (str): Path to the directory containing signature files.
        name (str): Name of the signature file to load, without extension.

    Returns:
        dict: Parsed JSON content of the signature file.
    """
    path = os.path.join(signatures_dir, "{}.json".format(name))
    with open(path) as f:
        return json.load(f)


def apply_visual_marking(service, finding):
    """Apply a background color to the addresses associated with a finding.

    Uses the finding's severity to determine the color from SEVERITY_COLORS.
    Skips external addresses. Colors are applied to the finding's address
    and all its cross-references.

    Args:
        service: Ghidra color service used to set background colors.
        finding: Finding object with severity, address, and xrefs attributes.
    """
    color = SEVERITY_COLORS.get(finding.severity)
    if not color:
        return

    if finding.address and "EXTERNAL" not in str(finding.address):
        service.setBackgroundColor(finding.address, finding.address, color)
    for xref in finding.xrefs:
        service.setBackgroundColor(xref, xref, color)


def create_bookmark(program, finding):
    """Create analysis bookmarks for the addresses associated with a finding.

    Places a bookmark at the finding's address and at each of its
    cross-references. Skips external addresses. The bookmark is categorized
    using the finding's category and annotated with its description.

    Args:
        program: The Ghidra program in which to create bookmarks.
        finding: Finding object with address, xrefs, category, and description
            attributes.
    """
    bm = program.getBookmarkManager()

    if finding.address and "EXTERNAL" not in str(finding.address):
        bm.setBookmark(finding.address, BookmarkType.ANALYSIS, finding.category.upper(), finding.description)

    for xref in finding.xrefs:
        bm.setBookmark(xref, BookmarkType.ANALYSIS, finding.category.upper(), finding.description)
        
        
def resolve_function_context(func_manager, addr):
    """Resolve a memory address to its containing function name and offset.

    Args:
        func_manager (FunctionManager): The function manager of the analyzed program.
        addr (Address): Address to resolve, typically a cross-reference origin.

    Returns:
        str: Human-readable location string. If the address falls inside a known
            function, returns 'func_name+0xOFFSET (0xADDR)' or 'func_name (0xADDR)'
            if the address is the function entry point. Falls back to the raw
            address string if no containing function is found.
    """
    func =  func_manager.getFunctionContaining (addr)
    if func is None:
        return str(addr)
    name = func.getName()
    offset = addr.subtract(func.getEntryPoint())
    if offset == 0:
        return f"{str(addr)} ({name})"
    return f"{str(addr)} ({name}+0x{offset:x})"