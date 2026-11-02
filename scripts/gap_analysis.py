#!/usr/bin/env python3
"""Knowledge-driven gap analysis: what SHOULD this stack have?

Given a target directory and a domain profile (website, api-service,
mcp-server, llm-app, cli-tool, library-sdk, iac-cloud, kubernetes,
ci-pipeline, mobile-app, desktop-app, data-pipeline - see
scripts/gap_profiles.json), diffs the domain's expected capabilities against
repo evidence (file presence + an optional audit report's fired rule IDs) and
cites the matching framework controls live from framework_metadata.json.

Statuses: present (evidence found), risk-observed (a scanner rule for this
capability fired - the need is confirmed AND the flaw is present),
must-build gap (must=true, nothing found), should-consider (nice-to-have,
nothing found). Families/keywords that match no control are reported under
unresolved_refs, never silently dropped.

    python scripts/gap_analysis.py <target> --domain website
    python scripts/gap_analysis.py <target> --domain api-service --audit-json report.json
    python scripts/gap_analysis.py <target> --domain auto --markdown reports/gaps.md
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

PROFILES_PATH = SCRIPTS_DIR / "gap_profiles.json"
METADATA_PATH = SCRIPTS_DIR / "framework_metadata.json"

AUDIT_EXCLUDES = (".git", "node_modules", "__pycache__", ".venv", "venv",
                  "target", "dist", "build", ".idea", ".vscode")


def load_profiles() -> dict:
    with open(PROFILES_PATH, encoding="utf-8") as f:
        return json.load(f)


def load_controls() -> dict:
    with open(METADATA_PATH, encoding="utf-8") as f:
        return json.load(f).get("controls", {})


def family_index(controls: dict) -> dict:
    index: dict = {}
    for key, value in controls.items():
        fam = key.split(":", 1)[0] if ":" in key else key
        text = value if isinstance(value, str) else json.dumps(value)
        index.setdefault(fam, []).append((key, text))
    return index


def cite(index: dict, families: list, keywords: list, top_k: int,
         unresolved: list, cap_id: str) -> list:
    cites = []
    for fam in families:
        entries = index.get(fam)
        if not entries:
            unresolved.append({"capability": cap_id, "family": fam})
            continue
        scored = []
        for key, text in entries:
            low = text.lower()
            hits = sum(1 for kw in keywords if kw.lower() in low)
            if hits:
                scored.append((hits, key, text))
        scored.sort(key=lambda t: (-t[0], t[1]))
        for _, key, text in scored[:top_k]:
            cites.append({"ref": key, "text": text[:220]})
    return cites


def walk_target(target: Path) -> list:
    rels = []
    for path in target.rglob("*"):
        try:
            if not path.is_file():
                continue
        except OSError:
            continue  # dead symlink or otherwise unstatable entry
        try:
            rel = path.relative_to(target).as_posix()
        except ValueError:
            continue
        if rel.split("/")[0].lower() in AUDIT_EXCLUDES:
            continue
        rels.append(rel)
    return rels


def evidence_for(cap: dict, rels: list) -> list:
    found = []
    lowered = [(r, r.lower(), r.lower().rsplit("/", 1)[-1]) for r in rels]
    for pattern in cap.get("files_any", []):
        pat = pattern.lower()
        for rel, low, base in lowered:
            if fnmatch.fnmatchcase(low, pat) or fnmatch.fnmatchcase(base, pat):
                found.append(rel)
                break
    return sorted(set(found))


def load_fired_rules(audit_json: str | None) -> set:
    if not audit_json:
        return set()
    with open(audit_json, encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", [])
    out = set()
    for item in findings:
        if isinstance(item, dict):
            rid = item.get("rule_id") or item.get("ruleId")
            if rid:
                out.add(str(rid))
    return out


def analyze(target: Path, domain: str, fired: set, index: dict,
            profiles: dict, top_k: int) -> dict:
    profile = profiles[domain]
    rels = walk_target(target)
    unresolved: list = []
    caps = []
    for cap in profile["capabilities"]:
        files = evidence_for(cap, rels)
        fired_rules = sorted(set(cap.get("rules_any", [])) & fired)
        citations = cite(index, cap.get("families", []),
                         cap.get("keywords", []), top_k, unresolved,
                         cap["id"])
        if fired_rules:
            status = "risk-observed"
        elif files:
            status = "present"
        elif cap.get("must"):
            status = "must-build gap"
        else:
            status = "should-consider"
        caps.append({"id": cap["id"], "title": cap["title"],
                     "must": bool(cap.get("must")),
                     "status": status, "evidence_files": files,
                     "fired_rules": fired_rules, "citations": citations})
    counts: dict = {}
    for c in caps:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return {"domain": domain, "label": profile.get("label", domain),
            "target": str(target), "summary": counts,
            "capabilities": caps, "unresolved_refs": unresolved}


def autodetect(rels: list, profiles: dict) -> str:
    best, best_score = None, -1
    for name, profile in profiles.items():
        if name.startswith("_"):
            continue
        score = 0
        for cap in profile["capabilities"]:
            if evidence_for(cap, rels):
                score += 2 if cap.get("must") else 1
        if score > best_score:
            best, best_score = name, score
    return best or "website"


def to_markdown(report: dict) -> str:
    lines = [f"# Gap analysis: {report['label']}",
             f"Target: `{report['target']}`",
             "",
             "## Summary",
             ""]
    for status, n in sorted(report["summary"].items()):
        lines.append(f"- {status}: {n}")
    lines += ["", "## Capabilities", ""]
    for c in report["capabilities"]:
        flag = "**MUST-BUILD GAP**" if c["status"] == "must-build gap" else c["status"]
        lines.append(f"### [{c['status']}] {c['title']}")
        if c["must"]:
            lines[lines.index(f"### [{c['status']}] {c['title']}")] += " (must)"
        lines.append(f"- status: {flag}")
        if c["evidence_files"]:
            lines.append(f"- evidence: {', '.join(c['evidence_files'][:6])}")
        if c["fired_rules"]:
            lines.append(f"- fired rules: {', '.join(c['fired_rules'])}")
        for cit in c["citations"]:
            lines.append(f"- {cit['ref']}: {cit['text']}")
        lines.append("")
    if report["unresolved_refs"]:
        lines += ["## Unresolved refs (profile needs fixing)", ""]
        for u in report["unresolved_refs"]:
            lines.append(f"- {u['capability']}: family `{u['family']}` not in KB")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff a domain's expected capabilities against repo evidence.")
    parser.add_argument("target", help="Directory to analyze")
    parser.add_argument("--domain", default="auto",
                        help="Profile name or 'auto' (default: auto)")
    parser.add_argument("--audit-json", default=None,
                        help="audit_repo.py --json output for risk-observed status")
    parser.add_argument("--markdown", default=None,
                        help="Write a Markdown report to this path")
    parser.add_argument("--top-k", type=int, default=2,
                        help="Citations per capability (default: 2)")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    profiles = {k: v for k, v in load_profiles().items() if not k.startswith("_")}
    if args.domain == "auto":
        domain = autodetect(walk_target(target), profiles)
        print(f"auto-detected domain: {domain}", file=sys.stderr)
    elif args.domain in profiles:
        domain = args.domain
    else:
        print(f"error: unknown domain '{args.domain}' "
              f"(choose from: {', '.join(sorted(profiles))})", file=sys.stderr)
        return 2
    report = analyze(target, domain, load_fired_rules(args.audit_json),
                     family_index(load_controls()), profiles, args.top_k)
    print(json.dumps(report, indent=2))
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(report), encoding="utf-8")
        print(f"markdown written to {args.markdown}", file=sys.stderr)
    musts = report["summary"].get("must-build gap", 0)
    risks = report["summary"].get("risk-observed", 0)
    print(f"{musts} must-build gaps, {risks} observed risks "
          f"({report['summary'].get('present', 0)} present)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
