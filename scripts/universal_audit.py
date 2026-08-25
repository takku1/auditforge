#!/usr/bin/env python3
"""AuditForge - Universal Compliance & Security Auditor CLI entrypoint.
Imports coordinating logic from the modular auditor package.
"""

import argparse
import sys
import os

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auditor import UniversalAuditor

def main():
    parser = argparse.ArgumentParser(description="AuditForge Compliance Orchestrator")
    parser.add_argument("directory", help="Directory to audit")
    parser.add_argument("--config", default="config/compliance_config.yaml", help="Path to config YAML")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format")
    args = parser.parse_args()

    auditor = UniversalAuditor(args.directory, args.config)
    auditor.run_checkov()
    auditor.run_semgrep()
    auditor.run_network_audit()
    auditor.run_trivy()
    auditor.run_dependency_audit()
    
    print(auditor.generate_report(args.format))

if __name__ == "__main__":
    main()
