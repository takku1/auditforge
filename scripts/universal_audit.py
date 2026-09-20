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
    parser.add_argument("--network-targets", default=None,
                         help="Comma-separated URLs to DAST-scan, overriding "
                              "config/compliance_config.yaml's network_targets "
                              "(which ships with placeholder example.com "
                              "defaults that are never scanned automatically)")
    args = parser.parse_args()

    auditor = UniversalAuditor(args.directory, args.config)
    auditor.run_checkov()
    auditor.run_semgrep()
    override_targets = (
        [t.strip() for t in args.network_targets.split(",") if t.strip()]
        if args.network_targets else None
    )
    auditor.run_network_audit(override_targets)
    auditor.run_email_audit()
    auditor.run_cloud_posture()
    auditor.run_sbom_audit()
    auditor.run_trivy()
    auditor.run_dependency_audit()
    auditor.run_cargo_audit()
    auditor.run_trufflehog()
    auditor.run_scorecard()
    auditor.run_nuclei(override_targets)

    print(auditor.generate_report(args.format))

if __name__ == "__main__":
    main()
