#!/usr/bin/env python3
"""SOC 2 static compliance auditor CLI entrypoint wrapper.
Exposes CLI scanning capability importing from the modular auditor package.
"""

import argparse
import sys
import os

# Add scripts directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auditor import audit_directory, SEVERITIES, SEVERITY_RANK
from auditor.reporting import print_text, to_json, to_sarif, to_markdown
from auditor.baseline import load_baseline, write_baseline

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="SOC 2 static compliance auditor "
                    "(secrets, IAM, encryption, TLS, SDLC hygiene)")
    parser.add_argument("directory", help="Directory to audit")
    parser.add_argument("--json", action="store_true",
                        help="Print the full report as JSON")
    parser.add_argument("--sarif", metavar="FILE",
                        help="Write a SARIF 2.1.0 report (GitHub code scanning)")
    parser.add_argument("--markdown", metavar="FILE",
                        help="Write a Markdown report")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="LOW",
                        help="Hide findings below this severity")
    parser.add_argument("--fail-on", choices=SEVERITIES + ["NEVER"],
                        default="NEVER",
                        help="Exit 1 if findings at/above this severity exist")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="GLOB",
                        help="Glob (relative, /-separated) to exclude; repeatable")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Suppress findings whose fingerprints are in this "
                             "baseline file")
    parser.add_argument("--update-baseline", metavar="FILE",
                        help="Write current findings' fingerprints to FILE")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.directory):
        parser.error(f"not a directory: {args.directory}")

    report = audit_directory(args.directory, excludes=args.exclude,
                             min_severity=args.min_severity)

    if args.update_baseline:
        write_baseline(args.update_baseline, report)
        print(f"Baseline written to {args.update_baseline} "
              f"({report['summary']['total']} fingerprints)", file=sys.stderr)

    if args.baseline:
        known = load_baseline(args.baseline)
        report["findings"] = [f for f in report["findings"]
                              if f.fingerprint not in known]
        summary = {s: 0 for s in SEVERITIES}
        for f in report["findings"]:
            summary[f.severity] += 1
        summary["total"] = len(report["findings"])
        report["summary"] = summary

    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(to_sarif(report))
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(report))

    if args.json:
        print(to_json(report))
    else:
        print_text(report, use_color=sys.stdout.isatty())

    if args.fail_on != "NEVER":
        threshold = SEVERITY_RANK[args.fail_on]
        gate_hits = sum(1 for f in report["findings"]
                        if SEVERITY_RANK[f.severity] <= threshold)
        if gate_hits:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
