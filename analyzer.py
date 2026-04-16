# This module serves as the main analyzer for the GhidraMAT framework, responsible for orchestrating the analysis process and coordinating the various modules.

# @author HalfTimeOfLife
# @category GhidraMAT
# @keybinding
# @menupath Analysis.GhidraMAT
# @toolbar

# Import necessary modules
import sys
import os
import importlib

script_dir = os.path.dirname(os.path.realpath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

for _mod_name in list(sys.modules.keys()):
    if _mod_name.startswith(("modules.", "core.", "utils.")):
        del sys.modules[_mod_name]

from core.context import Context
from core.finding import Finding
from core.report import generate_report
from utils.utils import get_imports, print_banner
from modules import anti_vm

MODULES = [
    anti_vm
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
  
  context = Context(currentProgram)
  findings = []
  
  for module in MODULES:
    print("GhidraMAT: running {}".format(module.__name__))
    try:
      mod_findings = module.analyze(context)
      findings.extend(mod_findings)
      print("[{}] {} finding(s)".format(module.__name__, len(mod_findings)))
    except Exception as e:
      print("[ERROR] {} failed: {}".format(module.__name__, str(e)))
      
  program_info = {
    "name": name,
    "path": str(path),
    "md5": program_md5,
    "sha256": program_sha256,
    "format": format,
    "date": creation_date
  }
  generate_report(findings, program_info, MODULES)


# Launch main analysis loop
run()

