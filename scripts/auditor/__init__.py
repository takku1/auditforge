from .models import Rule, Finding, UnifiedFinding
from .rules import RULES, RULES_BY_ID, SEVERITIES, SEVERITY_RANK
from .orchestrator import UniversalAuditor
from .scanners import scan_file

def _git_tracked_files(root: str):
    """Set of git-tracked paths (relative, /-separated) under root, or None
    if root isn't inside a git repo / git isn't on PATH - callers must treat
    None as "unavailable", not "nothing tracked". Computed once per scan
    rather than shelling out per-finding. See
    docs/field-test-roninai-2026-08-25.md §G2 (R-009): a scanner that can't
    tell tracked from untracked gives identical "rotate now" remediation to
    a secret that was never committed, which is wrong in both directions.
    """
    import subprocess
    try:
        result = subprocess.run(
            ["git", "-C", root, "ls-files"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore",
        )
    except (OSError, FileNotFoundError):
        return None
    if result.returncode != 0:
        return None
    return {line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()}


def audit_directory(root: str, excludes: list = None, min_severity: str = "LOW",
                     history: bool = False, disabled_rules: set = None,
                     pii_allow: list = None) -> dict:
    from .scanners import iter_files, scan_file, scan_git_history, scan_web_posture
    from datetime import datetime, timezone
    excludes = excludes or []
    disabled_rules = disabled_rules or set()
    pii_allow = pii_allow or []
    findings = []
    files_scanned = 0
    skipped = {"oversized": 0, "binary": 0, "unreadable": 0}
    for path, rel in iter_files(root, excludes):
        files_scanned += 1
        file_findings, skip_reason = scan_file(path, rel, pii_allow)
        if skip_reason:
            skipped[skip_reason] += 1
        findings.extend(file_findings)

    if history:
        findings.extend(scan_git_history(root, excludes, pii_allow=pii_allow))

    findings.extend(scan_web_posture(root, excludes))

    tracked = _git_tracked_files(root)
    if tracked is not None:
        for f in findings:
            if not f.historical:
                f.git_tracked = f.file.replace("\\", "/") in tracked

    if disabled_rules:
        findings = [f for f in findings if f.rule.id not in disabled_rules]

    threshold = SEVERITY_RANK[min_severity]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= threshold]
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.file, f.line))

    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        summary[f.severity] += 1
    summary["total"] = len(findings)

    import os
    return {
        "target": os.path.abspath(root),
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files_scanned": files_scanned,
        "skipped": skipped,
        "summary": summary,
        "findings": findings,
    }
