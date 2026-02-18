# This module provides functionality for detecting and analyzing anti-virtual machine (anti-VM) or anti-emulation techniques.

# @author HalfTimeOfLife
# @category GhidraMAT.modules

import json, os

def run(context):
    print("[anti_vm] Running anti-VM analysis...")
    findings = []
    
    # Check for common API call used in anti-VM
    api_signatures_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures", "signatures.json")
    if not os.path.exists(signatures_path):
        print("[anti_vm] No signatures file found at {}".format(signatures_path))
        return findings
    
    with open(signatures_path, "r") as f:
        signatures = json.load(f)
        
        
    
    print("[anti_vm] Anti-VM analysis completed.")
    return findings