import json
import os

from ghidra.program.model.listing import BookmarkType
from ghidra.app.plugin.core.colorizer import ColorizingService
from java.awt import Color

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
    print(BANNER)

def get_imports(context):
    imports = {}
    
    for symbol in context.symbol_table.getExternalSymbols():
        imports[symbol.getName()] = symbol.getAddress()
    
    return imports

def get_strings(context):
    strings = set()
    for s in context.listing.getDefinedData(True):
        if s.hasStringValue():
            strings.add(str(s.getValue()))
    return strings
    
def load_signatures(signatures_dir, name):
    path = os.path.join(signatures_dir, "{}.json".format(name))
    with open(path) as f:
        return json.load(f)
    
def apply_visual_marking(service, finding):
    color = SEVERITY_COLORS.get(finding.severity)
    if not color:
        return
    
    if finding.address and "EXTERNAL" not in str(finding.address):
        service.setBackgroundColor(finding.address, finding.address, color)

    for xref in finding.xrefs:
        service.setBackgroundColor(xref, xref, color)

def create_bookmark(program, finding):
    bm = program.getBookmarkManager()
    
    if finding.address and "EXTERNAL" not in str(finding.address):
        bm.setBookmark(finding.address, BookmarkType.ANALYSIS, finding.category.upper(), finding.description)
    
    for xref in finding.xrefs:
        bm.setBookmark(xref, BookmarkType.ANALYSIS, finding.category.upper(), finding.description)