class Context:
    def __init__(self, program, monitor=None):
        self.program = program
        self.monitor = monitor
        self.memory = program.getMemory()
        self.listing = program.getListing()
        self.symbol_table = program.getSymbolTable()
        self.ref_manager = program.getReferenceManager()
        self.func_manager = program.getFunctionManager()