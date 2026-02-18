# This module serves as the main analyzer for the GhidraMAT framework, responsible for orchestrating the analysis process and coordinating the various modules.

# @author HalfTimeOfLife
# @category GhidraMAT
# @keybinding
# @menupath Analysis.GhidraMAT.analyzer
# @toolbar

# Import necessary modules
import sys, os

from core.context import Context
from core.report import generate_report
from modules import anti_vm

# Modules list
MODULES = [
    anti_vm
]


# Banner
print(r"""
=======================================================
   _____ _     _     _           __  __       _______ 
  / ____| |   (_)   | |         |  \/  |   /\|__   __|
 | |  __| |__  _  __| |_ __ __ _| \  / |  /  \  | |   
 | | |_ | '_ \| |/ _` | '__/ _` | |\/| | / /\ \ | |   
 | |__| | | | | | (_| | | | (_| | |  | |/ ____ \| |   
  \_____|_| |_|_|\__,_|_|  \__,_|_|  |_/_/    \_\_|               
=======================================================
""")

# Extract basic information about the current program
name = currentProgram.getName()
path = currentProgram.getExecutablePath()
creation_date = currentProgram.getCreationDate()
format = currentProgram.getExecutableFormat()
program_md5 = currentProgram.getExecutableMD5()
program_sha256 = currentProgram.getExecutableSHA256()
base_image = currentProgram.getImageBase()


# Display basic information about the current program
print("Analyzing program: " + name)
print("Executable path: " + path)
print("Creation date: " + str(creation_date))
print("Executable format: " + format)
print("MD5: " + program_md5)
print("SHA256: " + program_sha256)
print("Base image address: " + str(base_image))

# Start of analysis
def run():
  print("\n[GhidraMAT] Starting analysis of " + name + "...\n")
  
  context = Context(currentProgram)
  findings = []
  
  for module in MODULES:
    print("GhidraMAT: running {}".format(module.__name__))
    try:
      findings = module.run(context)
      findings.extend(findings)
      print("[{}] {} finding(s)".format(module.__name__, len(findings)))
    except Exception as e:
      print("[ERROR] {} failed: {}".format(module.__name__, str(e)))

blocks = currentProgram.getMemory().getBlocks()
for block in blocks:
	print("Name: {}, Size: {}".format(block.getName(), block.getSize()))


# Launch main analysis loop
run()

