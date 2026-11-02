#!/usr/bin/env python3
"""Best-effort engine refresh (ROADMAP R-107 companion to check_freshness.py).

check_freshness.py *inventories* engine versions; this script *updates* what
can be updated safely offline-friendly:
  - nuclei: `nuclei -update-templates` (template refresh)
  - trivy: `trivy db --download-db-only` (vulnerability DB refresh)
  - semgrep: nothing to do (rulesets refresh on every run)
  - checkov/osv-scanner/scorecard/trufflehog/cargo-audit: versioned release
    installs - reported, never auto-upgraded (would change the binary).

Best-effort by design: every engine degrades to a status line, the script
always exits 0, and the freshness gate stays the strict one. Run before the
weekly gate so refreshed templates/DBs feed the new baseline:

    python scripts/update_engines.py [--json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys


def _version(tool: str) -> str:
    if shutil.which(tool) is None:
        return "missing"
    try:
        out = subprocess.run([tool, "--version"], capture_output=True,
                             text=True, timeout=30)
        line = (out.stdout or out.stderr).strip().splitlines()
        return line[0][:120] if line else "installed"
    except (OSError, subprocess.SubprocessError):
        return "installed (version query failed)"


def _refresh(tool: str, args: list, timeout: int = 600) -> dict:
    """Run an update command; never raise - result is a status dict."""
    if shutil.which(tool) is None:
        return {"status": "missing", "detail": "not installed"}
    try:
        out = subprocess.run([tool] + args, capture_output=True, text=True,
                             timeout=timeout)
        tail = (out.stdout or out.stderr).strip().splitlines()[-1:] or [""]
        if out.returncode == 0:
            return {"status": "updated", "detail": tail[0][:200]}
        return {"status": "failed",
                "detail": f"exit {out.returncode}: {tail[0][:200]}"}
    except subprocess.TimeoutExpired:
        return {"status": "failed",
                "detail": f"timed out after {timeout}s"}
    except OSError as exc:
        return {"status": "failed", "detail": str(exc)[:200]}


UPDATERS = {
    "nuclei": ["-update-templates"],
    "trivy": ["db", "--download-db-only"],
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Best-effort engine refresh.")
    parser.add_argument("--json", action="store_true",
                        help="Print the per-engine report as JSON")
    args = parser.parse_args(argv)

    report = {}
    for tool in ["checkov", "semgrep", "trivy", "osv-scanner", "nuclei",
                 "scorecard", "trufflehog", "cargo-audit"]:
        entry = {"version": _version(tool)}
        if tool in UPDATERS:
            entry.update(_refresh(tool, UPDATERS[tool]))
        else:
            entry.update({"status": "version-only",
                          "detail": "release install; not auto-upgraded"})
        report[tool] = entry

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for tool, entry in report.items():
            print(f"{tool}: {entry['status']} ({entry['version']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
