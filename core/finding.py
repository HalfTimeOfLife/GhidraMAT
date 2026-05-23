MAX_DISPLAY = 6


class Finding:
    """Represents a single detection result from the analysis.

    A finding is produced whenever a signature matches an import, string,
    byte pattern, or combination in the analyzed binary. It holds all
    metadata needed to describe, locate, and report the detection.

    Args:
        category (str): Analysis category the finding belongs to
            (e.g. "anti_vm", "anti_debug").
        type_of_technique (str): Detection method that produced this finding
            (e.g. "imports", "strings", "byte_patterns", "combinations").
        name (str): Name of the matched signature (e.g. API name, string value).
        severity (str): Severity level of the finding ("LOW", "MEDIUM", "HIGH",
            "CRITICAL").
        description (str): Human-readable description of the finding.
        combo_only (bool): If True, this finding is a weak standalone indicator
            and is only meaningful when part of a combination. Defaults to False.
        xrefs (list[Address]): Addresses that reference the matched symbol or
            string. Defaults to an empty list.
        xref_labels (list[str]): Human-readable location strings of the form
            '0xADDR (func_name+0xOFFSET)' or '0xADDR (func_name)', as produced
            by resolve_function_context.
        mitre (str): Technique: Sub-technique
        requirements (list[str]): Imports required for a combination finding.
            Defaults to None.

    Attributes:
        type (str): Detection method, stored from type_of_technique.
    """
    def __init__(self, category, type_of_technique, name, severity, description, combo_only=False, xrefs=None, xref_labels=None, mitre=None, requirements=None):
        self.category = category
        self.type = type_of_technique
        self.name = name
        self.severity = severity
        self.description = description
        self.combo_only = combo_only
        self.xrefs = xrefs or []
        self.xref_labels = xref_labels or []
        self.mitre = mitre if isinstance(mitre, str) else None
        self.requirements = requirements

    def to_dict(self):
        """Serialize the finding to a JSON-compatible dictionary.

        Returns:
            dict: A dictionary with keys category, type, name, severity, mitre,
                description, combo_only, xref_labels, and requirements.
                xref_labels contains human-readable location strings, not raw
                Ghidra Address objects.
        """
        return {
            "category": self.category,
            "type": self.type,
            "name": self.name,
            "severity": self.severity,
            "mitre": self.mitre,
            "description": self.description,
            "combo_only": self.combo_only,
            "xref_labels": self.xref_labels,
            "requirements": self.requirements
        }

    def __str__(self):
        """Format the finding as a human-readable report block.

        For byte_patterns, lists up to MAX_DISPLAY occurrence addresses, then
        appends '... and N more' if the total exceeds MAX_DISPLAY.
        For imports and strings, deduplicates by function name and shows a call
        count per function, also capped at MAX_DISPLAY distinct functions.

        Returns:
            str: Multi-line string with the finding name, severity, category,
                type, description, cross-references, requirements,
                and a combo-only warning if applicable.
        """

        note = "\n   [!] Standalone indicator weak -- meaningful only in combination" if self.combo_only else ""

        xrefs_str = ""
        if self.xref_labels:
            if self.type == "byte_patterns":
                labels = self.xref_labels[:MAX_DISPLAY]
                extra = len(self.xref_labels) - MAX_DISPLAY
                suffix = f", ... and {extra} more" if extra > 0 else ""
                xrefs_str = f"\n   Occurrences ({len(self.xref_labels)}) : {', '.join(labels)}{suffix}"
            else:
                seen = {}
                for label in self.xref_labels:
                    last_open = label.rfind("(")
                    if last_open != -1:
                        inner = label[last_open + 1:].rstrip(")")
                        fname = inner.split("+")[0]
                    else:
                        fname = label
                    seen[fname] = seen.get(fname, 0) + 1
                parts = [f"{fn} ({n}x)" if n > 1 else fn for fn, n in seen.items()]
                displayed = parts[:MAX_DISPLAY]
                extra = len(parts) - MAX_DISPLAY
                suffix = f", ... and {extra} more functions" if extra > 0 else ""
                xrefs_str = f"\n   Called from : {', '.join(displayed)}{suffix}"

        requirements_str = ""
        if self.requirements:
            requirements_formatted = ", ".join(str(x) for x in self.requirements)
            requirements_str = f"\n   Requires     : {requirements_formatted}"

        return (
            f"{self.name} "
            f"[{self.severity}] [{self.category}] [{self.type}]"
            f"\n   -> {self.description}"
            f"{requirements_str}"
            f"{xrefs_str}"
            f"{note}"
        )