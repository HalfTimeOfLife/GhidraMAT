def scan_byte_pattern(context, pattern_str):
    pattern = []
    for byte in pattern_str.split():
        if byte == "??":
            pattern.append(None)
        else:
            pattern.append(int(byte, 16))
    matches = []
    
    for block in context.memory.getBlocks():
        if not block.isExecute():
            continue
        
        size = block.getSize()
        # if size of block greater than 50 Mo we set the size to 50 Mo
        if size > 50000000:
            size = 50000000
        data = bytearray(size)
        start = block.getStart()
        try:
            for i in range(size):
                data[i] = block.getByte(start.add(i)) & 0xFF
        except MemoryAccessException as e:
            print("[WARNING] MemoryAccessException on block : ", start)
            continue
        
        for i in range(len(data) - len(pattern) + 1):
            if all(
                p is None or data[i + j] == p
                for j, p in enumerate(pattern)
            ):
                matches.append(start.add(i))
                
    return matches