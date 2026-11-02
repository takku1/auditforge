#!/usr/bin/env python3
"""Policy-document coverage audit: which governance policies exist?

Diffs the required-policy catalog (scripts/policy_profiles.json) against the
governance docs actually present in a target repo: filename hints plus
keyword hits inside small text docs (.md/.txt/.rst/.adoc). Framework
citations come live from framework_metadata.json via the shared helpers in
gap_analysis.py - families/keywords that match no control land in
unresolved_refs, never silently dropped.

Statuses: present (named file + substantive content), partial (filename
only, or content without a dedicated file), missing-must (must=true,
nothing found), should-consider (nice-to-have, nothing found).

    python scripts/policy_audit.py <target>
    python scripts/policy_audit.py <target> --markdown reports/policies.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

from gap_analysis import (  # noqa: E402
    cite,
    evidence_for,
    family_index,
    load_controls,
    walk_target,
)

PROFILES_PATH = SCRIPTS_DIR / "policy_profiles.json"
METADATA_PATH = SCRIPTS_DIR / "framework_metadata.json"

AUDIT_EXCLUDES = (".git", "node_modules", "__pycache__", ".venv", "venv",
                  "target", "dist", "build", ".idea", ".vscode")
TEXT_EXTS = {".md", ".txt", ".rst", ".adoc"}
MAX_BYTES = 300 * 1024


def load_policies() -> list:
    with open(PROFILES_PATH, encoding="utf-8") as f:
        return json.load(f)["policies"]


def read_text_docs(target: Path, rels: list) -> dict:
    """Map rel path -> lowercased text for small readable docs."""
    docs = {}
    for rel in rels:
        if Path(rel).suffix.lower() not in TEXT_EXTS:
            continue
        full = target / rel
        try:
            if full.stat().st_size > MAX_BYTES:
                continue
            docs[rel] = full.read_text(encoding="utf-8",
                                       errors="ignore").lower()
        except OSError:
            continue
    return docs


def content_hits(policy: dict, docs: dict) -> tuple:
    """(distinct keyword hits, {rel: [keywords]} for files with any hit)."""
    per_file = {}
    for rel, text in docs.items():
        hits = [kw for kw in policy.get("keywords", [])
                if kw.lower() in text]
        if hits:
            per_file[rel] = hits
    distinct = sorted({kw for hits in per_file.values() for kw in hits})
    return distinct, per_file


def analyze(target: Path, policies: list, index: dict, top_k: int) -> dict:
    rels = walk_target(target)
    docs = read_text_docs(target, rels)
    unresolved: list = []
    results = []
    for policy in policies:
        files = evidence_for(policy, rels)
        distinct, per_file = content_hits(policy, docs)
        citations = cite(index, policy.get("families", []),
                         policy.get("keywords", []), top_k, unresolved,
                         policy["id"])
        if files and len(distinct) >= 2:
            status = "present"
        elif files or len(distinct) >= 3:
            status = "partial"
        elif policy.get("must"):
            status = "missing (must)"
        else:
            status = "should-consider"
        results.append({"id": policy["id"], "title": policy["title"],
                        "must": bool(policy.get("must")),
                        "status": status, "evidence_files": files,
                        "matched_keywords": distinct[:8],
                        "content_files": sorted(per_file)[:6],
                        "citations": citations})
    counts: dict = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"target": str(target), "summary": counts,
            "policies": results, "unresolved_refs": unresolved}


def to_markdown(report: dict) -> str:
    lines = ["# Policy coverage audit",
             f"Target: `{report['target']}`",
             "", "## Summary", ""]
    for status, n in sorted(report["summary"].items()):
        lines.append(f"- {status}: {n}")
    lines += ["", "## Policies", ""]
    for p in report["policies"]:
        flag = ("**MISSING (must)**" if p["status"] == "missing (must)"
                else p["status"])
        lines.append(f"### [{p['status']}] {p['title']}")
        if p["must"]:
            lines[-1] += " (must)"
        lines.append(f"- status: {flag}")
        if p["evidence_files"]:
            lines.append("- evidence: " + ", ".join(p["evidence_files"][:6]))
        if p["matched_keywords"]:
            lines.append("- keywords: " + ", ".join(p["matched_keywords"]))
        for cit in p["citations"]:
            lines.append(f"- {cit['ref']}: {cit['text']}")
        lines.append("")
    if report["unresolved_refs"]:
        lines += ["## Unresolved refs (catalog needs fixing)", ""]
        for u in report["unresolved_refs"]:
            lines.append(f"- {u['capability']}: family `{u['family']}` not in KB")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit governance/policy document coverage of a repo.")
    parser.add_argument("target", help="Directory to analyze")
    parser.add_argument("--markdown", default=None,
                        help="Write a Markdown report to this path")
    parser.add_argument("--top-k", type=int, default=2,
                        help="Citations per policy (default: 2)")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    report = analyze(target, load_policies(),
                     family_index(load_controls()), args.top_k)
    print(json.dumps(report, indent=2))
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(report), encoding="utf-8")
        print(f"markdown written to {args.markdown}", file=sys.stderr)
    missing = report["summary"].get("missing (must)", 0)
    partial = report["summary"].get("partial", 0)
    print(f"{missing} missing-must, {partial} partial "
          f"({report['summary'].get('present', 0)} present)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
