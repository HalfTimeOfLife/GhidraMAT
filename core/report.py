from core.finding import Finding
import os
from modules import anti_vm
from utils.utils import *
from datetime import datetime

VERSION = "0.1"
REPORTS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "reports")

MODULES = [
    anti_vm
]

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
    
    lines.append("-" * 60)
    lines.append("")
    
    return lines

def generate_report(findings, program_info):
    # Placeholder for report generation logic
    print("\nGenerating report...")
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    now = datetime.now().astimezone()
    timestamp = now.strftime("%d-%m-%Y_%Hh%Mmin%Ss")
    filename = os.path.join(REPORTS_DIR, f"report_{program_info['name']}_{timestamp}.txt")
    
    lines = []
    lines.extend(build_header(program_info, findings))

    
    # Might be adding new banner for the report
    #lines.append(BANNER)
    
    SEPARATOR  = "=" * 60
    SUBSEP     = "-" * 40
    SUBSUBSEP  = "*" * 40

    # Display per module (anti-vm, anti-debug, etc)
    for module in MODULES:
        module_name = module.__name__.replace("modules.", "").upper()
        lines.append("")
        lines.append(SEPARATOR)
        lines.append(f"  MODULE : {module_name}")
        lines.append(SEPARATOR)
        
        module_findings = [f for f in findings if f.category == module_name.lower()]
        
        if not module_findings:
            lines.append("  No findings detected.")
            continue
        
        # Dipslay per types (imports, strings, byte patterns, combinations)
        for sign_type in TYPES:
            lines.append("")
            lines.append(SUBSEP)
            lines.append(f"TYPE : {sign_type}")
            lines.append(SUBSEP)
            type_findings = [f for f in module_findings if f.type == sign_type]
            if not type_findings:
                continue
            
            # Display per severity (LOW, MEDIUM, HIGH, CRITICAL)
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
    
    output = "\n".join(lines)
    
    # Console
    print(output)
    
    # File
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)
            
            

    
