from ghidra.program.model.mem import MemoryAccessException

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
        
        if context.monitor and context.monitor.isCancelled():
            print("[GhidraMAT] Scan cancelled by user.")
            return matches
        
        size = block.getSize()
        if size > 50000000:
            size = 50000000
        data = bytearray(size)
        start = block.getStart()
        
        if context.monitor:
            context.monitor.setMessage(
                "[GhidraMAT] Scanning block {} ({} bytes)".format(str(start), size)
            )
        
        try:
            for i in range(size):
                data[i] = block.getByte(start.add(i)) & 0xFF
        except MemoryAccessException as e:
            print("[WARNING] MemoryAccessException on block : ", start)
            continue
        
        for i in range(len(data) - len(pattern) + 1):
            
            if context.monitor and context.monitor.isCancelled():
                context.monitor.setMessage("[GhidraMAT] Scan cancelled by user.")
                return matches
            
            if all(
                p is None or data[i + j] == p
                for j, p in enumerate(pattern)
            ):
                matches.append(start.add(i))
                
    return matches