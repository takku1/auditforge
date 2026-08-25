import json
from datetime import datetime, timezone
from typing import Dict, List
from .rules import SEVERITIES, RULES_BY_ID

ANSI = {
    "CRITICAL": "\x1b[1;31m", "HIGH": "\x1b[31m",
    "MEDIUM": "\x1b[33m", "LOW": "\x1b[36m", "reset": "\x1b[0m",
}


def print_text(report: dict, use_color: bool):
    def paint(sev: str) -> str:
        if not use_color:
            return f"[{sev}]"
        return f"{ANSI[sev]}[{sev}]{ANSI['reset']}"

    print(f"SOC 2 audit of {report['target']}")
    print(f"Files scanned: {report['files_scanned']}\n")
    for f in report["findings"]:
        ctx = " (test/example context)" if f.in_test_context else ""
        print(f"{paint(f.severity):<22} {f.rule.id} {f.rule.name}"
              f" [{', '.join(f.rule.controls)}]{ctx}")
        print(f"    {f.file}:{f.line}")
        print(f"    {f.snippet}")
        print(f"    Fix: {f.rule.remediation}")
    s = report["summary"]
    print(f"\nAudit complete: {s['total']} findings "
          f"(Critical: {s['CRITICAL']} | High: {s['HIGH']} | "
          f"Medium: {s['MEDIUM']} | Low: {s['LOW']})")


def to_json(report: dict) -> str:
    out = dict(report)
    out["findings"] = [f.to_dict() for f in report["findings"]]
    return json.dumps(out, indent=2)


def to_sarif(report: dict) -> str:
    sarif_level = {"CRITICAL": "error", "HIGH": "error",
                   "MEDIUM": "warning", "LOW": "note"}
    rules_used = sorted({f.rule.id for f in report["findings"]})
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
                   "master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "auditforge",
                "informationUri": "https://github.com/local/auditforge",
                "rules": [{
                    "id": rid,
                    "name": RULES_BY_ID[rid].name,
                    "shortDescription": {"text": RULES_BY_ID[rid].name},
                    "help": {"text": RULES_BY_ID[rid].remediation},
                    "properties": {
                        "soc2_controls": list(RULES_BY_ID[rid].controls),
                    },
                } for rid in rules_used],
            }},
            "results": [{
                "ruleId": f.rule.id,
                "level": sarif_level[f.severity],
                "message": {"text": f"{f.rule.name}: {f.rule.remediation}"},
                "partialFingerprints": {"soc2AuditFingerprint": f.fingerprint},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    },
                }],
            } for f in report["findings"]],
        }],
    }
    return json.dumps(sarif, indent=2)


def to_markdown(report: dict) -> str:
    s = report["summary"]
    lines = [
        "# AuditForge - SOC 2 Compliance Audit Report",
        "",
        f"- **Target:** `{report['target']}`",
        f"- **Scanned:** {report['scanned_at']} ({report['files_scanned']} files)",
        f"- **Findings:** {s['total']} "
        f"(Critical: {s['CRITICAL']}, High: {s['HIGH']}, "
        f"Medium: {s['MEDIUM']}, Low: {s['LOW']})",
        "",
    ]
    for sev in SEVERITIES:
        group = [f for f in report["findings"] if f.severity == sev]
        if not group:
            continue
        lines += [f"## {sev.title()} ({len(group)})", "",
                  "| Rule | SOC 2 | Location | Snippet |",
                  "| --- | --- | --- | --- |"]
        for f in group:
            snippet = f.snippet.replace("|", "\\|").replace("`", "'")
            lines.append(f"| {f.rule.id} {f.rule.name} "
                         f"| {', '.join(f.rule.controls)} "
                         f"| `{f.file}:{f.line}` | `{snippet}` |")
        lines.append("")
    return "\n".join(lines)


# Reporting functions for universal_audit
def to_universal_markdown(findings: list, mapping_data: dict, metadata_data: dict, summary: dict) -> str:
    lines = [
        "# AuditForge - Universal Compliance & Security Audit Report",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive Summary",
        f"- **Total Findings:** {summary['total']}",
        f"- **Critical/High Risk:** {summary['critical'] + summary['high']}",
        "",
        "| Severity | Count |",
        "| --- | --- |",
        f"| CRITICAL | {summary['critical']} |",
        f"| HIGH | {summary['high']} |",
        f"| MEDIUM | {summary['medium']} |",
        f"| LOW | {summary['low']} |",
        "",
        "## Findings Matrix",
        "| Tool | Rule | File | Frameworks & Controls | Severity |",
        "| --- | --- | --- | --- | --- |"
    ]
    for f in findings:
        fw_list = []
        for fw in f.frameworks:
            desc = metadata_data.get("controls", {}).get(fw)
            if desc:
                fw_list.append(f"**{fw}**: {desc[:100]}...")
            else:
                fw_list.append(fw)
        fw_str = "<br>".join(fw_list) if fw_list else "N/A"
        lines.append(f"| {f.tool} | {f.rule_id} | `{f.file}:{f.line}` | {fw_str} | {f.severity} |")
    
    lines.append("\n## Framework Definitions (Parsed)")
    for fw, desc in mapping_data.get("frameworks", {}).items():
        lines.append(f"- **{fw}:** {desc}")

    return "\n".join(lines)


def to_universal_json(findings: list, summary: dict) -> str:
    return json.dumps({"summary": summary, "findings": [f.__dict__ for f in findings]}, indent=2)
