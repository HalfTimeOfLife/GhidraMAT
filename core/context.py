class Context:
    """Holds references to the main Ghidra program accessors.

    Centralizes the most commonly used managers and accessors
    of a Ghidra program, so they don't need to be retrieved
    individually in each function.

    Args:
        program: The Ghidra program to analyze.
        monitor: Optional progress monitor for long-running tasks.

    Attributes:
        memory: Memory map of the program.
        listing: Disassembled listing of the program.
        symbol_table: Symbol table of the program.
        ref_manager: Cross-reference manager.
        func_manager: Function manager.
    """
    def __init__(self, program, monitor=None):
        self.program = program
        self.monitor = monitor
        self.memory = program.getMemory()
        self.listing = program.getListing()
        self.symbol_table = program.getSymbolTable()
        self.ref_manager = program.getReferenceManager()
        self.func_manager = program.getFunctionManager()