from .models import Rule, Finding, UnifiedFinding
from .rules import RULES, RULES_BY_ID, SEVERITIES, SEVERITY_RANK
from .orchestrator import UniversalAuditor
from .scanners import scan_file

def audit_directory(root: str, excludes: list = None, min_severity: str = "LOW") -> dict:
    from .scanners import iter_files, scan_file
    from datetime import datetime, timezone
    excludes = excludes or []
    findings = []
    files_scanned = 0
    for path, rel in iter_files(root, excludes):
        files_scanned += 1
        findings.extend(scan_file(path, rel))

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
        "summary": summary,
        "findings": findings,
    }
