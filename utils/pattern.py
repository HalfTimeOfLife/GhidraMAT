def scan_byte_pattern(context, pattern_str):
    """Search for a byte pattern within all decoded instructions of the program.

    Parses a space-separated hex pattern string where "??" acts as a wildcard,
    then searches all instructions in the program listing for matching sequences.

    Args:
        context (Context): Analysis context of the target program.
        pattern_str (str): Space-separated hex byte pattern to search for.

    Returns:
        list[Address]: List of addresses where the pattern was found.
    """
    pattern = []
    for b in pattern_str.split():
        if b == "??":
            pattern.append(None)
        else:
            pattern.append(int(b, 16))

    matches = []
    listing = context.program.getListing()

    for instr in listing.getInstructions(True):
        # getBytes() returns signed bytes; convert to unsigned before comparison.
        unsigned_bytes = [b & 0xFF for b in instr.getBytes()]
        for i in range(len(unsigned_bytes) - len(pattern) + 1):
            if all(
                p is None or unsigned_bytes[i + j] == p for j, p in enumerate(pattern)
            ):
                matches.append(instr.getMinAddress().add(i))
                break

    # Scan non-executable sections (data) for crypto constants
    for block in context.memory.getBlocks():
        if block.isExecute() or not block.isInitialized():
            continue
        addr = block.getStart()
        size = int(block.getSize())
        # Read byte by byte to avoid Java<->Python array bridge issue
        buf = [context.memory.getByte(addr.add(i)) & 0xFF for i in range(size)]
        for i in range(len(buf) - len(pattern) + 1):
            if all(p is None or buf[i + j] == p for j, p in enumerate(pattern)):
                matches.append(addr.add(i))

    return matches
