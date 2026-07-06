"""tests/fakes.py

Fake Ghidra objects used to test the detection engine without a Ghidra runtime.
"""

# -------------------------------------------------------------------
# --- primitives ---
# -------------------------------------------------------------------

class FakeAddress:
    """Minimal stand-in for a Ghidra Address object."""
    def __init__(self, offset, is_external=False):
        self.offset = offset
        self._is_external = is_external

    def add(self, n):
        return FakeAddress(self.offset + n)

    def subtract(self, other):
        return self.offset - other.offset

    def isExternalAddress(self):
        return self._is_external

    def __eq__(self, other):
        return isinstance(other, FakeAddress) and self.offset == other.offset

    def __hash__(self):
        return hash(self.offset)

    def __str__(self):
        return f"0x{self.offset:x}"


class FakeSymbol:
    """Minimal stand-in for a Ghidra Symbol object, as returned by
    SymbolTable.getExternalSymbols()."""
    def __init__(self, name, address):
        self._name = name
        self._address = address

    def getName(self):
        return self._name

    def getAddress(self):
        return self._address


class FakeData:
    """Minimal stand-in for a Ghidra Data object (defined string data), as
    returned by Listing.getDefinedData()."""
    def __init__(self, value, address, has_string_value=True):
        self._value = value
        self._address = address
        self._has_string_value = has_string_value

    def hasStringValue(self):
        return self._has_string_value

    def getValue(self):
        return self._value

    def getAddress(self):
        return self._address


class FakeFunction:
    """Minimal stand-in for a Ghidra Function object, as returned by
    FunctionManager.getFunctionContaining()."""
    def __init__(self, name, entry_point):
        self._name = name
        self._entry_point = entry_point

    def getName(self):
        return self._name

    def getEntryPoint(self):
        return self._entry_point


class FakeInstruction:
    """Minimal stand-in for a Ghidra Instruction object, as returned by
    Listing.getInstructions()."""
    def __init__(self, min_address, byte_values):
        self._min_address = min_address
        self._bytes = byte_values

    def getBytes(self):
        return self._bytes

    def getMinAddress(self):
        return self._min_address


class FakeReference:
    """Minimal stand-in for a Ghidra Reference object, as returned by
    ReferenceManager.getReferencesTo()."""
    def __init__(self, from_address):
        self._from_address = from_address

    def getFromAddress(self):
        return self._from_address

# -------------------------------------------------------------------
# --- managers ---
# -------------------------------------------------------------------

class FakeSymbolTable:
    """Minimal stand-in for a Ghidra SymbolTable, as returned by
    program.getSymbolTable()."""
    def __init__(self, symbols=None):
        self._symbols = symbols or []

    def getExternalSymbols(self):
        return self._symbols


class FakeListing:
    """Minimal stand-in for a Ghidra Listing, as returned by
    program.getListing(). Backs both defined-data lookups (used for strings)
    and instruction iteration (used for byte pattern scanning)."""
    def __init__(self, data=None, instructions=None):
        self._data = data or []
        self._instructions = instructions or []

    def getDefinedData(self, forward):
        return self._data

    def getInstructions(self, forward):
        return self._instructions


class FakeRefManager:
    """Minimal stand-in for a Ghidra ReferenceManager, as returned by
    program.getReferenceManager()."""
    def __init__(self, refs_by_address=None):
        self._refs_by_address = refs_by_address or {}

    def getReferencesTo(self, address):
        return self._refs_by_address.get(address, [])


class FakeFuncManager:
    """Minimal stand-in for a Ghidra FunctionManager, as returned by
    program.getFunctionManager()."""
    def __init__(self, function_by_address=None):
        self._function_by_address = function_by_address or {}

    def getFunctionContaining(self, addr):
        return self._function_by_address.get(addr)


class FakeMemoryBlock:
    """Minimal stand-in for a Ghidra MemoryBlock. Not used by the current
    scan_byte_pattern implementation (which iterates instructions instead),
    but kept for any code path that still walks raw memory blocks."""
    def __init__(self, start, content_bytes, is_execute=True):
        self.start = start
        self._bytes = content_bytes
        self._is_execute = is_execute

    def isExecute(self):
        return self._is_execute

    def getSize(self):
        return len(self._bytes)

    def getStart(self):
        return self.start

    def getBytes(self, start, data, offset, size):
        for i in range(size):
            data[offset + i] = self._bytes[i]


class FakeMemory:
    """Minimal stand-in for a Ghidra Memory object, as returned by
    program.getMemory()."""
    def __init__(self, blocks=None):
        self._blocks = blocks or []

    def getBlocks(self):
        return self._blocks


class FakeProgram:
    """Minimal stand-in for a Ghidra Program object. Only exposes getListing(),
    which is what utils.pattern.scan_byte_pattern calls directly via
    context.program (as opposed to context.listing, used for strings)."""
    def __init__(self, listing=None):
        self._listing = listing or FakeListing()

    def getListing(self):
        return self._listing


class FakeMonitor:
    """Minimal stand-in for a Ghidra TaskMonitor. Records every message passed
    to setMessage() so tests can assert on progress reporting."""
    def __init__(self, cancelled=False):
        self._cancelled = cancelled
        self.messages = []

    def setMessage(self, msg):
        self.messages.append(msg)

    def isCancelled(self):
        return self._cancelled

# -------------------------------------------------------------------
# --- context ---
# -------------------------------------------------------------------

class FakeContext:
    """Minimal stand-in for core.context.Context, built from fakes.

    Every attribute defaults to an empty fake, so a test only needs to
    provide the specific manager(s) relevant to what it's exercising.
    """
    def __init__(self, symbol_table=None, listing=None, ref_manager=None,
                 func_manager=None, memory=None, monitor=None, program=None):
        self.symbol_table = symbol_table or FakeSymbolTable()
        self.listing = listing or FakeListing()
        self.ref_manager = ref_manager or FakeRefManager()
        self.func_manager = func_manager or FakeFuncManager()
        self.memory = memory or FakeMemory()
        self.monitor = monitor
        self.program = program or FakeProgram()