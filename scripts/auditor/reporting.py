import json
import os
from datetime import datetime, timezone
from typing import Optional
from .rules import SEVERITIES, RULES_BY_ID

ANSI = {
    "CRITICAL": "\x1b[1;31m", "HIGH": "\x1b[31m",
    "MEDIUM": "\x1b[33m", "LOW": "\x1b[36m", "reset": "\x1b[0m",
}

_CROSSWALK_CACHE = None


def _load_crosswalk() -> dict:
    """framework_mappings.json's rule-id -> [\"Framework:ref\", ...] crosswalk,
    cached after first load. Missing/unreadable file degrades to {} rather
    than failing - audit_repo.py stays usable standalone either way.
    """
    global _CROSSWALK_CACHE
    if _CROSSWALK_CACHE is None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "framework_mappings.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                _CROSSWALK_CACHE = json.load(f).get("mappings", {})
        except (OSError, json.JSONDecodeError):
            _CROSSWALK_CACHE = {}
    return _CROSSWALK_CACHE


def rule_frameworks(rule) -> list:
    """A rule's baked-in SOC2 controls plus any cross-framework crosswalk
    entries for its rule ID from framework_mappings.json. That crosswalk data
    existed but never reached audit_repo.py's own output before this - only
    the universal_audit.py orchestrator path consulted it. See
    docs/gap-status-2026-09-02-update.md §4.
    """
    # Prefix the rule's own SOC2 refs to match the crosswalk's "Framework:ref"
    # shape, so a rule with both a native "CC6.1" and a crosswalked
    # "SOC2:CC6.1" doesn't show the same fact twice in two notations.
    merged = [f"SOC2:{c}" for c in rule.controls]
    for extra in _load_crosswalk().get(rule.id, []):
        if extra not in merged:
            merged.append(extra)
    return merged


def print_text(report: dict, use_color: bool):
    def paint(sev: str) -> str:
        if not use_color:
            return f"[{sev}]"
        return f"{ANSI[sev]}[{sev}]{ANSI['reset']}"

    print(f"SOC 2 audit of {report['target']}")
    print(f"Files scanned: {report['files_scanned']}")
    skipped = report.get("skipped") or {}
    skip_total = sum(skipped.values())
    if skip_total:
        parts = ", ".join(f"{n} {reason}" for reason, n in skipped.items() if n)
        print(f"Files skipped: {skip_total} ({parts}) - not scanned, not \"scanned clean\"")
    print()
    for f in report["findings"]:
        ctx = " (test/example context)" if f.in_test_context else ""
        if f.historical:
            ctx += f" (history: commit {f.commit})" if f.commit else " (history)"
        print(f"{paint(f.severity):<22} {f.rule.id} {f.rule.name}"
              f" [{', '.join(rule_frameworks(f.rule))}]{ctx}")
        print(f"    {f.file}:{f.line}")
        print(f"    {f.snippet}")
        print(f"    Fix: {f.effective_remediation}")
    s = report["summary"]
    print(f"\nAudit complete: {s['total']} findings "
          f"(Critical: {s['CRITICAL']} | High: {s['HIGH']} | "
          f"Medium: {s['MEDIUM']} | Low: {s['LOW']})")


def to_json(report: dict) -> str:
    out = dict(report)
    findings = []
    for f in report["findings"]:
        d = f.to_dict()
        d["soc2_controls"] = rule_frameworks(f.rule)
        findings.append(d)
    out["findings"] = findings
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
                        "soc2_controls": rule_frameworks(RULES_BY_ID[rid]),
                    },
                } for rid in rules_used],
            }},
            "results": [{
                "ruleId": f.rule.id,
                "level": sarif_level[f.severity],
                "message": {"text": f"{f.rule.name}: {f.effective_remediation}"},
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
    skipped = report.get("skipped") or {}
    skip_total = sum(skipped.values())
    lines = [
        "# AuditForge - SOC 2 Compliance Audit Report",
        "",
        f"- **Target:** `{report['target']}`",
        f"- **Scanned:** {report['scanned_at']} ({report['files_scanned']} files)",
        f"- **Findings:** {s['total']} "
        f"(Critical: {s['CRITICAL']}, High: {s['HIGH']}, "
        f"Medium: {s['MEDIUM']}, Low: {s['LOW']})",
    ]
    if skip_total:
        parts = ", ".join(f"{n} {reason}" for reason, n in skipped.items() if n)
        lines.append(f"- **Skipped (not scanned):** {skip_total} ({parts})")
    lines.append("")
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
                         f"| {', '.join(rule_frameworks(f.rule))} "
                         f"| `{f.file}:{f.line}` | `{snippet}` |")
        lines.append("")
    return "\n".join(lines)


# Reporting functions for universal_audit
def _availability_lines(availability: dict) -> list:
    if not availability:
        return []
    installed = sum(1 for v in availability.values() if v)
    lines = [
        "## External Engine Availability",
        f"{installed}/{len(availability)} external engines available on this "
        "host - findings from an unavailable engine are absent because it "
        "never ran, not because the scan came back clean.",
        "",
        "| Engine | Installed |",
        "| --- | --- |",
    ]
    for name, ok in availability.items():
        lines.append(f"| {name} | {'yes' if ok else 'no'} |")
    lines.append("")
    return lines


def to_universal_markdown(findings: list, mapping_data: dict, metadata_data: dict, summary: dict,
                           availability: Optional[dict] = None) -> str:
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
        *_availability_lines(availability or {}),
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


def to_universal_json(findings: list, summary: dict, availability: Optional[dict] = None) -> str:
    return json.dumps({
        "summary": summary,
        "engine_availability": availability or {},
        "findings": [f.__dict__ for f in findings],
    }, indent=2)
