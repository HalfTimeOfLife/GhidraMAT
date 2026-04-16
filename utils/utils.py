import json

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

def load_signatures(path, name):
    with open(path) as f:
        return json.load(f)[name]
    
    
def apply_visual_marking(findings):
    return