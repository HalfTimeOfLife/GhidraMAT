# This module serves as the main analyzer for the GhidraMAT framework, responsible for orchestrating the analysis process and coordinating the various modules.

# @author HalfTimeOfLife
# @category GhidraMAT
# @keybinding ctrl shift A
# @menupath Analysis.GhidraMAT
# @toolbar ghidramat_icon.png
# @runtime PyGhidra

import os
import sys
from datetime import datetime

script_dir = os.path.dirname(os.path.realpath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Force reload of local modules to avoid stale Ghidra script cache.
for _mod_name in list(sys.modules.keys()):
    if _mod_name.startswith(("modules.", "core.", "utils.")):
        del sys.modules[_mod_name]

from ghidra.app.plugin.core.colorizer import ColorizingService

from core.context import Context
from core.report import generate_json, generate_report
from utils.detection import analyze
from utils.utils import apply_visual_marking, create_bookmark, print_banner

CATEGORIES = [
    "anti_vm",
    "anti_debug",
    "packer",
    "network",
    "crypto",
    "injection",
    "persistence",
    "impair_defenses",
]


def _get_program_info():
    return {
        "name": currentProgram.getName(),
        "path": str(currentProgram.getExecutablePath()),
        "md5": currentProgram.getExecutableMD5(),
        "sha256": currentProgram.getExecutableSHA256(),
        "format": currentProgram.getExecutableFormat(),
        "date": str(currentProgram.getCreationDate()),
    }


def run():
    """Run the full GhidraMAT analysis on the current program."""

    program_info = _get_program_info()
    print_banner()
    print("Analyzing program: " + program_info["name"])
    print("Executable path: " + program_info["path"])
    print("Creation date: " + program_info["date"])
    print("Executable format: " + program_info["format"])
    print("MD5: " + program_info["md5"])
    print("SHA256: " + program_info["sha256"])
    print("Base image address: " + str(currentProgram.getImageBase()))
    print("\n[GhidraMAT] Starting analysis of " + program_info["name"] + "...\n")

    context = Context(currentProgram, monitor)
    findings = []

    for category in CATEGORIES:
        if context.monitor:
            context.monitor.setMessage(f"[GhidraMAT] Running {category}...")
        print(f"GhidraMAT: running {category}")
        try:
            mod_findings = analyze(context, category)
            findings.extend(mod_findings)
            print(f"[{category}] {len(mod_findings)} finding(s)")
        except Exception as e:
            print(f"[ERROR] {category} failed: {e!s}")

    service = state.getTool().getService(ColorizingService)
    transaction = currentProgram.startTransaction("GhidraMAT markings")
    try:
        for finding in findings:
            create_bookmark(currentProgram, finding)
            apply_visual_marking(service, finding)
    finally:
        currentProgram.endTransaction(transaction, True)

    now = datetime.now().astimezone()

    generate_report(findings, program_info, CATEGORIES, now)
    generate_json(findings, program_info, CATEGORIES, now)


run()
