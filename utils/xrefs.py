def get_xrefs_to_symbol(context, api_name):
    xrefs = []
    for symbol in context.symbol_table.getExternalSymbols():
        if symbol.getName() == api_name:
            for ref in context.ref_manager.getReferencesTo(symbol.getAddress()):
                xrefs.append(ref.getFromAddress())
    return xrefs

def get_xrefs_to_string(context, string_value):
    xrefs = []
    for s in context.listing.getDefinedData(True):
        if s.hasStringValue() and str(s.getValue()) == string_value:
            for ref in context.ref_manager.getReferencesTo(s.getAddress()):
                xrefs.append(ref.getFromAddress())
    return xrefs