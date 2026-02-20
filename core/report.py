import core.finding
import os
from utils.utils import *
from datetime import datetime

VERSION = "0.1"
REPORTS_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "reports")

def generate_report(findings, program_info):
    # Placeholder for report generation logic
    print("\nGenerating report...")
    
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    now = datetime.now().astimezone()
    timestamp = now.strftime("%d-%m-%Y_%Hh%Mmin%Ss_%Z")
    filename = os.path.join(REPORTS_DIR, f"report_{program_info['name']}_{timestamp}.txt")
    
    lines = []
    
    # Might be adding new banner for the report
    #lines.append(BANNER)
    
    output = "\n".join(lines)
    
    # Console
    print(output)
    
    # Fichier
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)
            
            

    
