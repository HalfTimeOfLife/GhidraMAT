# This module serves as the main analyzer for the GhidraMAT framework, responsible for orchestrating the analysis process and coordinating the various modules.

# @author HalfTimeOfLife
# @category GhidraMAT
# @keybinding
# @menupath Analysis.GhidraMAT
# @toolbar

# Import necessary modules
import sys
import os

script_dir = os.path.dirname(os.path.realpath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

for _mod_name in list(sys.modules.keys()):
    if _mod_name.startswith(("modules.", "core.", "utils.")):
        del sys.modules[_mod_name]

from ghidra.app.plugin.core.colorizer import ColorizingService

from core.context import Context
from core.report import generate_report
from utils.utils import print_banner, apply_visual_marking, create_bookmark
from utils.detection import analyze

CATEGORIES = [
    "anti_vm",
    "anti_debug",
    "packer",
    "network",
    "crypto",
    "injection",
    "persistence",
    "evasion"
]

# Extract basic information about the current program
name = currentProgram.getName()
path = currentProgram.getExecutablePath()
creation_date = currentProgram.getCreationDate()
format = currentProgram.getExecutableFormat()
program_md5 = currentProgram.getExecutableMD5()
program_sha256 = currentProgram.getExecutableSHA256()
base_image = currentProgram.getImageBase()

# Start of analysis
def run():
  
  # Display banner
  print_banner()
  
  # Display basic information about the current program
  print("Analyzing program: " + name)
  print("Executable path: " + path)
  print("Creation date: " + str(creation_date))
  print("Executable format: " + format)
  print("MD5: " + program_md5)
  print("SHA256: " + program_sha256)
  print("Base image address: " + str(base_image))
  print("\n[GhidraMAT] Starting analysis of " + name + "...\n")
  
  context = Context(currentProgram, monitor)
  findings = []
  
  for category in CATEGORIES:
    if context.monitor:
        context.monitor.setMessage("[GhidraMAT] Running {}...".format(category))
    print("GhidraMAT: running {}".format(category))
    try:
        mod_findings = analyze(context, category)
        findings.extend(mod_findings)
        print("[{}] {} finding(s)".format(category, len(mod_findings)))
    except Exception as e:
        print("[ERROR] {} failed: {}".format(category, str(e)))
        
    service = state.getTool().getService(ColorizingService)
    transaction = currentProgram.startTransaction("GhidraMAT markings")
    try:
        for finding in findings:
            create_bookmark(currentProgram, finding)
            
            apply_visual_marking(service, finding)
    finally:
        currentProgram.endTransaction(transaction, True)
      
  program_info = {
    "name": name,
    "path": str(path),
    "md5": program_md5,
    "sha256": program_sha256,
    "format": format,
    "date": creation_date
  }
  generate_report(findings, program_info, CATEGORIES)


# Launch main analysis loop
run()

