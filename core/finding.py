class Finding:
    """Represents a single detection result from the analysis.

    A finding is produced whenever a signature matches an import, string,
    byte pattern, or combination in the analyzed binary. It holds all
    metadata needed to describe, locate, and report the detection.

    Args:
        category (str): Analysis category the finding belongs to
            (e.g. "anti-vm", "anti-debug").
        type_of_technique (str): Detection method that produced this finding
            (e.g. "imports", "strings", "byte_patterns", "combinations").
        name (str): Name of the matched signature (e.g. API name, string value).
        severity (str): Severity level of the finding ("LOW", "MEDIUM", "HIGH",
            "CRITICAL").
        address (Address): Memory address of the match, or None if not applicable.
        description (str): Human-readable description of the finding.
        combo_only (bool): If True, this finding is a weak standalone indicator
            and is only meaningful when part of a combination. Defaults to False.
        xrefs (list[Address]): Addresses that reference the matched symbol or
            string. Defaults to an empty list.
        func_offset (str): String of the function + offset where the finding 
            is located.
        requirements (list[str]): Imports required for a combination finding.
            Defaults to None.

    Attributes:
        type (str): Detection method, stored from type_of_technique.
    """
    def __init__(self, category, type_of_technique, name, severity, address, description, combo_only=False, xrefs=None, xref_labels=None, requirements=None):
        self.category = category
        self.type = type_of_technique
        self.name = name
        self.severity = severity
        self.address = address
        self.description = description
        self.combo_only = combo_only
        self.xrefs = xrefs or []
        self.xref_labels = xref_labels or []
        self.requirements = requirements
    
    def __str__(self):
        """Format the finding as a human-readable report block.

        Returns:
            str: Multi-line string with the finding name, severity, category,
                type, address, description, cross-references, requirements,
                and a combo-only warning if applicable.
        """
        
        addr_str = ""
        if self.address and "EXTERNAL" not in str(self.address):
            addr_str = f"\n   @ {str(self.address)}"

        note = "\n   [!] Standalone indicator weak -- meaningful only in combination" if self.combo_only else ""

        xrefs_str = ""
        if self.xref_labels:
            if self.type == "byte_patterns":
                labels_formatted = ", ".join(self.xref_labels)
                xrefs_str = f"\n   Occurrences ({len(self.xref_labels)}) : {labels_formatted}"
            else:
                labels_formatted = ", ".join(self.xref_labels)
                xrefs_str = f"\n   Called from : {labels_formatted}"
                

        requirements_str = ""
        if self.requirements:
            requirements_formatted = ", ".join(str(x) for x in self.requirements)
            requirements_str = f"\n   Requires     : {requirements_formatted}"

        return (
            f"{self.name} "
            f"[{self.severity}] [{self.category.upper()}] [{self.type}]"
            f"{addr_str}"
            f"\n   -> {self.description}"
            f"{requirements_str}"
            f"{xrefs_str}"
            f"{note}"
        )