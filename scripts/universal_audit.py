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
    parser = argparse.ArgumentParser(
        description="AuditForge Compliance Orchestrator",
        epilog="Run inside the project .venv (the plugin launcher "
               "resolves AUDITFORGE_HOME/.venv automatically): a Linux-built .venv "
               "on Windows leaves dead lib64 symlinks and starves dependency "
               "resolution - recreate the venv on the host OS instead.")
    parser.add_argument("directory", help="Directory to audit")
    parser.add_argument("--config", default="config/compliance_config.yaml", help="Path to config YAML")
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown", help="Output format")
    parser.add_argument("--engines", default=None,
                        help="Comma-separated engine subset (default: all). "
                             "Engines: checkov,semgrep,trivy,osv,cargo_audit,"
                             "network,email,cloud,sbom,nuclei,scorecard,trufflehog")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass the deterministic-engine result cache")
    parser.add_argument("--no-parallel", action="store_true",
                        help="Run engines sequentially (debug aid)")
    parser.add_argument("--email-domains", default=None,
                        help="Comma-separated mail domains to SPF/DKIM/DMARC-check, "
                             "overriding email_auth.domains from config (lets a "
                             "local DAST run against localhost still check the "
                             "production mail domain)"),
    parser.add_argument("--network-targets", default=None,
                        help="Comma-separated URLs to DAST-scan, overriding "
                             "config/compliance_config.yaml's network_targets "
                             "(which ships with placeholder example.com "
                             "defaults that are never scanned automatically)")
    args = parser.parse_args()

    from auditor.orchestrator import ENGINE_METHODS
    engines = None
    if args.engines:
        engines = [e.strip() for e in args.engines.split(",") if e.strip()]
        unknown = [e for e in engines if e not in ENGINE_METHODS]
        if unknown:
            parser.error(f"unknown engines: {unknown} (choose from {', '.join(ENGINE_METHODS)})")

    auditor = UniversalAuditor(args.directory, args.config,
                               use_cache=not args.no_cache)
    override_targets = (
        [t.strip() for t in args.network_targets.split(",") if t.strip()]
        if args.network_targets else None
    )
    override_email = (
        [d.strip() for d in args.email_domains.split(",") if d.strip()]
        if args.email_domains else None
    )
    auditor.run_all(engines=engines, network_targets=override_targets,
                    email_domains=override_email,
                    parallel=not args.no_parallel)

    print(auditor.generate_report(args.format))

if __name__ == "__main__":
    main()
