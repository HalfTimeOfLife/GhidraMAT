def get_xrefs_to_symbol(context, api_name):
    """Retrieve cross-references to an external symbol by name.

    Searches the symbol table for an external symbol matching the given name,
    then collects all addresses that reference it.

    Args:
        context (Context): Analysis context of the target program.
        api_name (str): Name of the external symbol to look up (e.g. "CreateFileW").

    Returns:
        list[Address]: List of addresses referencing the symbol.
    """
    xrefs = []
    for symbol in context.symbol_table.getExternalSymbols():
        if symbol.getName() == api_name:
            for ref in context.ref_manager.getReferencesTo(symbol.getAddress()):
                xrefs.append(ref.getFromAddress())
    return xrefs


def get_xrefs_to_string(context, string_value):
    """Retrieve cross-references to a defined string by value.

    Searches all defined data in the listing for a string matching the given
    value, then collects all addresses that reference it.

    Args:
        context (Context): Analysis context of the target program.
        string_value (str): Exact string value to search for.

    Returns:
        list[Address]: List of addresses referencing the string.
    """
    xrefs = []
    for s in context.listing.getDefinedData(True):
        if s.hasStringValue() and str(s.getValue()) == string_value:
            for ref in context.ref_manager.getReferencesTo(s.getAddress()):
                xrefs.append(ref.getFromAddress())
    return xrefs