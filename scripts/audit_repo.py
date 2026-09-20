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

CONFIG_FILENAME = ".soc2rc.yml"


def load_repo_config(directory: str) -> dict:
    """Discovers `<directory>/.soc2rc.yml` (excludes, min_severity,
    disable_rules) so consumers stop rediscovering the same CLI incantations
    every time - see ROADMAP R-014. Returns {} if the file doesn't exist or
    fails to parse (never fatal - CLI flags alone still work standalone).
    Schema:
        exclude: ["generated/*", ...]
        min_severity: MEDIUM
        disable_rules: ["SDLC004", ...]
    """
    path = os.path.join(directory, CONFIG_FILENAME)
    if not os.path.isfile(path):
        return {}
    try:
        import yaml
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as exc:  # noqa: BLE001 - malformed config degrades to "no config", not a crash
        print(f"warning: {path} could not be parsed ({exc}); ignoring it", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _warn_if_output_inside_scan(output_path: str, scan_dir: str) -> None:
    """R-023: writing a report file inside the directory being scanned means
    a later run of the same command re-scans its own prior output - findings
    embedded as example text/snippets get matched as if they were real,
    producing a self-referential feedback loop (hit this exact bug this
    session scanning scripts/ while writing a report into scripts/).
    """
    out_abs = os.path.abspath(output_path)
    scan_abs = os.path.abspath(scan_dir)
    try:
        common = os.path.commonpath([out_abs, scan_abs])
    except ValueError:
        return  # different drives on Windows - can't be inside, nothing to warn about
    if common == scan_abs and out_abs != scan_abs:
        print(f"warning: output path {output_path!r} is inside the directory being "
              f"scanned ({scan_dir!r}) - a later run will re-scan this report's own "
              "content; consider writing outside the scan target (e.g. reports/)",
              file=sys.stderr)


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
    parser.add_argument("--min-severity", choices=SEVERITIES, default=None,
                        help="Hide findings below this severity "
                             "(default: LOW, or .soc2rc.yml's min_severity)")
    parser.add_argument("--fail-on", choices=SEVERITIES + ["NEVER"],
                        default="NEVER",
                        help="Exit 1 if findings at/above this severity exist")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="GLOB",
                        help="Glob (relative, /-separated) to exclude; repeatable. "
                             "Combined with .soc2rc.yml's exclude list, if present.")
    parser.add_argument("--history", action="store_true",
                        help="Also scan git history (`git log -p --all`) for "
                             "secrets deleted from HEAD but still recoverable - "
                             "slower than a working-tree-only scan")
    parser.add_argument("--baseline", metavar="FILE",
                        help="Suppress findings whose fingerprints are in this "
                             "baseline file")
    parser.add_argument("--update-baseline", metavar="FILE",
                        help="Write current findings' fingerprints to FILE")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.directory):
        parser.error(f"not a directory: {args.directory}")

    repo_config = load_repo_config(args.directory)
    min_severity = args.min_severity or repo_config.get("min_severity") or "LOW"
    if min_severity not in SEVERITIES:
        parser.error(f"{CONFIG_FILENAME}: invalid min_severity {min_severity!r} "
                     f"(must be one of {SEVERITIES})")
    excludes = list(args.exclude) + list(repo_config.get("exclude") or [])
    disabled_rules = set(repo_config.get("disable_rules") or [])

    report = audit_directory(args.directory, excludes=excludes,
                             min_severity=min_severity, history=args.history,
                             disabled_rules=disabled_rules)

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
        _warn_if_output_inside_scan(args.sarif, args.directory)
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(to_sarif(report))
    if args.markdown:
        _warn_if_output_inside_scan(args.markdown, args.directory)
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
