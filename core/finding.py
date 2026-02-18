class Finding:
    def __init__(self, category, name, severity, address, description):
        self.category = category
        self.name = name
        self.severity = severity
        self.address = address
        self.description = description
        
    def __str__(self):
        addr = str(self.address) if self.address else "N/A"
        return f"{self.category} - {self.name} at {addr}: {self.description}"