class Finding:
    def __init__(self, category, type_of_technique, name, severity, address, description, combo_only=False):
        self.category = category
        self.type = type_of_technique
        self.name = name
        self.severity = severity
        self.address = address
        self.description = description
        self.combo_only = combo_only
    
    def __str__(self):
        addr_str = ""
        if self.address and "EXTERNAL" not in str(self.address):
            addr_str = f"\n   @ {str(self.address)}"

        note = "\n   [!] Standalone indicator weak — meaningful only in combination" if self.combo_only else ""

        return (
            f"{self.name}"
            f"[{self.severity}] [{self.category.upper()}] [{self.type}] "
            f"{addr_str}"
            f"\n   -> {self.description}"
            f"{note}"
        ).encode('ascii', errors='replace').decode('ascii')