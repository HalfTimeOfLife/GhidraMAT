import os
from utils.utils import *
from datetime import datetime

VERSION = "0.1"
REPORTS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "reports")

SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW"
]

TYPES = [
    "imports",
    "strings",
    "byte_patterns",
    "combinations"
]

def build_header(program_info, findings):
    """Build the report header lines with program metadata and a findings summary.

    Produces a formatted header block containing the banner, program information,
    and a per-category breakdown of findings grouped by detection type.

    Args:
        program_info (dict): Metadata about the analyzed program, expected keys:
            name, path, format, md5, sha256, date.
        findings (list[Finding]): All findings from the analysis.

    Returns:
        list[str]: Lines of the report header, ready to be joined and written.
    """
    lines = []
    
    lines.append(BANNER)
    
    lines.append("=" * 60)
    lines.append("  ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"  Program     : {program_info['name']}")
    lines.append(f"  Path        : {program_info['path']}")
    lines.append(f"  Format      : {program_info['format']}")
    lines.append(f"  MD5         : {program_info['md5']}")
    lines.append(f"  SHA256      : {program_info['sha256']}")
    lines.append(f"  Date        : {program_info['date']}")
    lines.append("")
    
    lines.append("-" * 60)
    lines.append("  SUMMARY")
    lines.append("-" * 60)
    
    total = len(findings)
    lines.append(f"  Total findings : {total}")
    lines.append("")
    
    categories = set(f.category for f in findings)
    for cat in sorted(categories):
        cat_findings = [f for f in findings if f.category == cat]
        
        n_imports     = len([f for f in cat_findings if f.type == "imports" and not f.combo_only])
        n_strings     = len([f for f in cat_findings if f.type == "strings"])
        n_bytes       = len([f for f in cat_findings if f.type == "byte_patterns"])
        n_combos      = len([f for f in cat_findings if f.type == "combinations"])
        n_combo_only  = len([f for f in cat_findings if f.combo_only])
        
        lines.append(
            f"  {cat:<20} : {len(cat_findings)} findings "
            f"({n_imports} imports, {n_strings} strings, "
            f"{n_bytes} byte_patterns, {n_combos} combinations, "
            f"{n_combo_only} combo_only)"
        )
        
        mitre_ids = sorted(set(
            f.mitre for f in cat_findings if f.mitre
        ))
        if mitre_ids:
            lines.append(f"  {'MITRE':<20} :  {', '.join(mitre_ids)}")
    
    lines.append("-" * 60)
    lines.append("")
    
    return lines

def generate_report(findings, program_info, categories):
    """Generate and write a formatted analysis report to disk and console.

    Builds a full text report by combining a header with a per-category
    breakdown of findings, organized by detection type and severity.
    Within each severity level, combo-only findings are separated from
    regular ones and flagged as weak standalone indicators.

    The report is printed to the console and saved as a .txt file in
    REPORTS_DIR, with a timestamped filename.

    Args:
        findings (list[Finding]): All findings from the analysis.
        program_info (dict): Metadata about the analyzed program, expected
            keys: name, path, format, md5, sha256, date.
        categories (list[str]): Ordered list of categories to include
            in the report (e.g. ["anti-vm", "anti-debug"]).
    """
    
    print("\nGenerating report...")
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    now = datetime.now().astimezone()
    timestamp = now.strftime("%d-%m-%Y_%Hh%Mmin%Ss")
    filename = os.path.join(REPORTS_DIR, f"report_{program_info['name']}_{timestamp}.txt")
    
    lines = []
    lines.extend(build_header(program_info, findings))
    
    SEPARATOR  = "=" * 60
    SUBSEP     = "-" * 40
    SUBSUBSEP  = "*" * 40

    for category in categories:
        category_name = category.upper()
        lines.append("")
        lines.append(SEPARATOR)
        lines.append(f"  CATEGORY : {category_name}")
        lines.append(SEPARATOR)
        
        category_findings = [f for f in findings if f.category == category_name.lower()]
        
        if not category_findings:
            lines.append("  No findings detected.")
            continue
        
        for sign_type in TYPES:
            lines.append("")
            lines.append(SUBSEP)
            lines.append(f"TYPE : {sign_type}")
            lines.append(SUBSEP)
            type_findings = [f for f in category_findings if f.type == sign_type]
            if not type_findings:
                continue
            
            for severity in SEVERITY_ORDER:
                severity_findings = [f for f in type_findings if f.severity == severity]
                if not severity_findings:
                    continue
                    
                lines.append("")
                lines.append(f"  [ {severity} ]")
                lines.append(SUBSUBSEP)
                
                normal   = [f for f in severity_findings if not f.combo_only]
                combonly = [f for f in severity_findings if f.combo_only]
                
                for f in normal:
                    lines.append(f"  {f.__str__()}")
                
                if combonly:
                    lines.append("")
                    lines.append("  -- Weak standalone indicators --")
                    for f in combonly:
                        lines.append(f"  {f.__str__()}")
        
        lines.append("")
    
    lines.append("")
    lines.append(SEPARATOR)
    lines.append("  END OF REPORT")
    lines.append(SEPARATOR)
    
    output = "\n".join(lines)
    
    print(output)
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)
            
            

    
