#!/usr/bin/env python3
"""AuditForge freshness pipeline: detect silent rot in the knowledge stack.

Builds a live snapshot (framework family counts, KB commits, engine
versions, KEV catalog IDs, derived-index staleness, calendar watches) and
diffs it against the tracked baseline `scripts/freshness_manifest.json`:

    python scripts/check_freshness.py                 # compare, exit 1 on regression
    python scripts/check_freshness.py --write         # compare, then save as new baseline
    python scripts/check_freshness.py --skip-kev      # no network (KEV diff skipped)
    python scripts/check_freshness.py --max-drop-pct 5

Regression gates (exit 1): a tracked family vanished or hit 0 controls, any
family or the global total dropped more than --max-drop-pct (default 10%) -
the signature of an upstream format change silently breaking a parser (the
ASVS R-032 bug class). New KEV IDs are *signal, not failure*: they print as
WATCH items (newly exploited CVEs to triage) and never fail the run. Offline
or missing tools degrade to warnings, never errors.

Intended caller: `.github/workflows/freshness.yml` (weekly) runs
update_sources.ps1, then --check (fail stops the train), then --write,
then commits the manifest + framework_metadata.json. Locally, run the same
two commands after `pwsh scripts/update_sources.ps1`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = SCRIPTS_DIR / "freshness_manifest.json"
METADATA_PATH = SCRIPTS_DIR / "framework_metadata.json"
VECTOR_INDEX_PATH = SCRIPTS_DIR / "vector_index.db"
DOCUMENT_CATALOG_PATH = SCRIPTS_DIR / "document_catalog.db"

sys.path.insert(0, str(SCRIPTS_DIR))

# Mirror of scripts/update_sources.ps1 $sources registry (nested SAF paths
# included). If the registry gains a repo, add it here too.
KB_SOURCES = [
    "comply", "jupiterone-policies", "nist-csf", "gdpr-checklist",
    "security-templates", "probo", "comp-ai", "opengrc", "oscal-content",
    "attack-stix-data", "atlas-data", "d3fend-ontology", "compliance-as-code",
    "asvs", "owasp-top10", "owasp-api-security", "owasp-mobile-top10",
    "owasp-llm-top10", "owasp-mcp-top10", "owasp-k8s-top10", "owasp-cicd-top10",
    "owasp-masvs", "secure-controls-framework", "fedramp-rules",
    "mitre-saf-cis/aws-foundations-cis-baseline",
    "mitre-saf-cis/azure-foundations-cis-baseline",
    "mitre-saf-cis/eks-cis-cluster-baseline",
    "mitre-saf-cis/gcp-cis-benchmark",
    "mitre-saf-cis/gke-cis-benchmark",
    "mitre-saf-cis/rhel8-stig-baseline",
    "mitre-saf-cis/rhel9-stig-baseline",
    "juice-shop",
]

# Mirror of the update_sources.ps1 tool inventory, plus cargo-audit (a
# configured universal_audit.py engine). Missing engines warn, never fail.
ENGINES = ["checkov", "semgrep", "trivy", "osv-scanner", "nuclei",
           "scorecard", "trufflehog", "cargo-audit"]

# Calendar watch (automation of ROADMAP R-049's manual watch). `due: None`
# means "tracked, no fixed date". Stored in the manifest so dates are
# versioned, not tribal knowledge.
WATCHES = [
    {"id": "CMMC Phase 2 mandatory cert",
     "due": "2026-11-10",
     "note": "Coverage via 800-171 + SCF CMMC rows; re-sync before date."},
    {"id": "EU CRA vulnerability-reporting obligations",
     "due": "2026-09-11",
     "note": "Live; coverage via SCF EU CRA 2024 rows - confirm KB sync current."},
    {"id": "DISA STIG quarterly drops",
     "due": None,
     "note": "Manual re-drop of current quarter zips into references/disa-stig/."},
    {"id": "PCI DSS next version",
     "due": None,
     "note": "Indexed parse is 4.0.1; watch for a successor."},
    {"id": "NIST OSCAL content revisions",
     "due": None,
     "note": "800-53 Rev 5.2.0 (May 2026); pulls flow via oscal-content."},
]


def _family_counts(controls: dict) -> dict[str, int]:
    counts: dict[str, int] = {}
    for key in controls:
        fam = key.split(":", 1)[0] if ":" in key else key
        counts[fam] = counts.get(fam, 0) + 1
    return counts


def collect_kb_state(root: Path) -> dict[str, dict]:
    state: dict[str, dict] = {}
    for name in KB_SOURCES:
        d = root / name
        if not d.is_dir():
            state[name] = {"commit": None, "date": None, "status": "missing"}
            continue
        try:
            out = subprocess.run(
                ["git", "-C", str(d), "log", "-1", "--format=%H|%cs"],
                capture_output=True, text=True, timeout=30)
            if out.returncode != 0:
                raise OSError(out.stderr.strip()[:100])
            commit, _, date = out.stdout.strip().partition("|")
            state[name] = {"commit": commit[:12], "date": date or None,
                           "status": "ok"}
        except (OSError, FileNotFoundError) as exc:
            state[name] = {"commit": None, "date": None,
                           "status": f"unavailable ({exc})"}
    return state


def collect_engine_state() -> dict[str, str]:
    state: dict[str, str] = {}
    for tool in ENGINES:
        if shutil.which(tool) is None:
            state[tool] = "missing"
            continue
        try:
            out = subprocess.run([tool, "--version"], capture_output=True,
                                 text=True, timeout=15)
            line = (out.stdout or out.stderr).strip().splitlines()
            state[tool] = (line[0][:120] if line else "installed")
        except (OSError, subprocess.SubprocessError):
            state[tool] = "installed (version query failed)"
    return state


def collect_kev_state(skip: bool) -> dict:
    if skip:
        return {"status": "skipped", "fetched_at": None, "count": 0, "ids": []}
    try:
        import vuln_intel  # noqa: E402
        ids, fetched_at = vuln_intel.kev_catalog_ids()
        return {"status": "ok", "fetched_at": fetched_at,
                "count": len(ids), "ids": ids}
    except Exception as exc:  # noqa: BLE001 - offline degrades to warning
        return {"status": f"offline ({exc})", "fetched_at": None,
                "count": 0, "ids": []}


def collect_derived_state() -> dict:
    meta_mtime = METADATA_PATH.stat().st_mtime if METADATA_PATH.exists() else 0
    idx_exists = VECTOR_INDEX_PATH.exists()
    stale = (idx_exists and METADATA_PATH.exists()
             and VECTOR_INDEX_PATH.stat().st_mtime < meta_mtime)
    return {"vector_index": {"present": idx_exists, "stale": bool(stale)}}


def build_live_state(root: Path, skip_kev: bool) -> dict:
    with open(METADATA_PATH, encoding="utf-8") as f:
        metadata = json.load(f)
    controls = metadata.get("controls", {})
    counts = _family_counts(controls)
    labels = metadata.get("frameworks", {})
    return {
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "generator": "scripts/check_freshness.py v1",
        "framework_metadata": {"controls": len(controls),
                               "families": len(counts)},
        "families": {fam: {"controls": counts[fam],
                           "label": labels.get(fam, "")}
                     for fam in sorted(counts)},
        "knowledge_bases": collect_kb_state(root),
        "engines": collect_engine_state(),
        "kev": collect_kev_state(skip_kev),
        "derived": collect_derived_state(),
        "watches": WATCHES,
    }


def _drop_pct(old: int, new: int) -> float:
    if old <= 0:
        return 0.0 if new <= 0 else 100.0
    return (old - new) / old * 100.0


def evaluate(old: dict | None, new: dict, today: str,
             max_drop_pct: float) -> dict:
    """Pure diff of baseline `old` vs live `new`. No IO, no network."""
    errors, warnings, info = [], [], []
    kev_new, kev_dropped = [], []
    if old is None:
        info.append("no baseline manifest - run with --write to record one")
        return {"errors": errors, "warnings": warnings, "info": info,
                "kev_new": kev_new, "kev_dropped": kev_dropped}

    old_fams = old.get("families", {})
    new_fams = new.get("families", {})
    for fam, entry in sorted(old_fams.items()):
        n_old = entry.get("controls", 0)
        if fam not in new_fams:
            errors.append(f"family vanished: {fam} ({n_old} controls in baseline)")
            continue
        n_new = new_fams[fam].get("controls", 0)
        if n_new == 0 and n_old > 0:
            errors.append(f"family zeroed: {fam} (was {n_old} controls)")
        elif _drop_pct(n_old, n_new) > max_drop_pct:
            errors.append(
                f"family shrank: {fam} {n_old} -> {n_new} "
                f"({_drop_pct(n_old, n_new):.1f}% > {max_drop_pct}% gate)")
    for fam, entry in sorted(new_fams.items()):
        if fam not in old_fams:
            info.append(f"new family: {fam} ({entry.get('controls', 0)} controls)")
    t_old = old.get("framework_metadata", {}).get("controls", 0)
    t_new = new.get("framework_metadata", {}).get("controls", 0)
    if _drop_pct(t_old, t_new) > max_drop_pct:
        errors.append(
            f"total controls shrank: {t_old} -> {t_new} "
            f"({_drop_pct(t_old, t_new):.1f}% > {max_drop_pct}% gate)")

    old_kb = old.get("knowledge_bases", {})
    for name, kb in sorted(new.get("knowledge_bases", {}).items()):
        prev = old_kb.get(name, {})
        if kb["status"] != "ok":
            warnings.append(f"KB unverifiable: {name} ({kb['status']})")
        elif kb.get("commit") != prev.get("commit"):
            info.append(f"KB updated: {name} "
                        f"{prev.get('commit', '?')} -> {kb.get('commit')}")

    old_eng = old.get("engines", {})
    for tool, ver in sorted(new.get("engines", {}).items()):
        prev = old_eng.get(tool, "missing")
        if ver == "missing" and prev != "missing":
            warnings.append(f"engine disappeared: {tool} (was: {prev})")
        elif ver != "missing" and prev == "missing":
            info.append(f"engine appeared: {tool} ({ver})")
        elif ver != prev:
            info.append(f"engine updated: {tool} ({ver})")

    kev = new.get("kev", {})
    if kev.get("status") == "ok":
        old_ids = set(old.get("kev", {}).get("ids", []))
        if old.get("kev", {}).get("status") != "ok" or not old_ids:
            info.append(f"KEV baseline recorded ({kev['count']} IDs)")
        else:
            new_ids = set(kev["ids"])
            kev_new = sorted(new_ids - old_ids)
            kev_dropped = sorted(old_ids - new_ids)
            if kev_dropped:
                info.append(f"KEV removals (catalog corrections): {len(kev_dropped)}")
    elif kev.get("status") == "skipped":
        info.append("KEV diff skipped (--skip-kev)")
    else:
        warnings.append(f"KEV diff unavailable: {kev.get('status')}")

    if new.get("derived", {}).get("vector_index", {}).get("stale"):
        warnings.append("semantic index older than framework_metadata.json "
                        "- rebuild via python scripts/build_vector_index.py")
    if not new.get("derived", {}).get("vector_index", {}).get("present"):
        info.append("vector_index.db absent locally (gitignored, rebuildable)")

    for w in new.get("watches", []):
        due = w.get("due")
        if not due:
            continue
        delta = (datetime.date.fromisoformat(due)
                 - datetime.date.fromisoformat(today)).days
        if delta < 0:
            warnings.append(f"WATCH past-due: {w['id']} (due {due}) - {w['note']}")
        elif delta <= 30:
            warnings.append(f"WATCH due in {delta}d: {w['id']} ({due}) - {w['note']}")

    return {"errors": errors, "warnings": warnings, "info": info,
            "kev_new": kev_new, "kev_dropped": kev_dropped}


def format_report(result: dict, new: dict, max_drop_pct: float) -> str:
    md = new.get("framework_metadata", {})
    lines = [f"controls={md.get('controls')} families={md.get('families')} "
             f"(gate: family/total drop > {max_drop_pct}%)"]
    if result["kev_new"]:
        lines.append("")
        lines.append(f"WATCH - {len(result['kev_new'])} new KEV entr"
                     f"{'y' if len(result['kev_new']) == 1 else 'ies'} "
                     f"(exploited in the wild - triage):")
        lines.extend(f"  + {cve}" for cve in result["kev_new"][:50])
        if len(result["kev_new"]) > 50:
            lines.append(f"  ... and {len(result['kev_new']) - 50} more")
    for section in ("errors", "warnings", "info"):
        items = result[section]
        if not items:
            continue
        lines.append("")
        lines.append(f"{section.upper()} ({len(items)}):")
        lines.extend(f"  - {m}" for m in items)
    if not result["errors"] and not result["warnings"] and not result["info"] \
            and not result["kev_new"]:
        lines.append("clean - no drift since baseline")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Diff the live knowledge stack against the freshness baseline.")
    parser.add_argument("--write", action="store_true",
                        help="Save the live snapshot as the new baseline manifest.")
    parser.add_argument("--max-drop-pct", type=float, default=10.0,
                        help="Fail when a family/total drops more than this percent.")
    parser.add_argument("--skip-kev", action="store_true",
                        help="Skip the KEV network fetch (offline runs).")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH),
                        help="Baseline manifest path.")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest)
    live = build_live_state(ROOT, args.skip_kev)
    old = None
    if manifest_path.exists():
        with open(manifest_path, encoding="utf-8") as f:
            old = json.load(f)

    today = datetime.date.today().isoformat()
    result = evaluate(old, live, today, args.max_drop_pct)
    print(format_report(result, live, args.max_drop_pct))

    if result["errors"]:
        print("\nFRESHNESS GATE FAILED - baseline NOT overwritten. Fix the "
              "parser/upstream issue, then re-run.", file=sys.stderr)
        return 1
    if args.write:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(live, f, indent=2)
            f.write("\n")
        print(f"\nbaseline written to {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
