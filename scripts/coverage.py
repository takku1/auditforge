#!/usr/bin/env python3
"""Deterministic coverage-hunting support (ROADMAP R-139).

Agents hunt; this module does the bookkeeping no agent should improvise:

  init    Partition recon output (entry-surfaces x trust-boundaries x
          subsystems x attack-classes) into per-run coverage units that
          validate clean under scripts/validate_coverage_ledger.py.
  critic  Deterministic gapfind over a ledger: unworked units, candidates
          without evidence, unsubstantiated coverage, terminal states
          without reasons. An unexplored surface stays uncovered - the
          critic, not the hunter's memory, says what was missed.
  budget  Account waves/attempts against a profile (quick/standard/deep)
          and report whether the critic + validation reserve is intact.
  carry   Additive-run rules: stamp prior_status onto a fresh ledger from
          a prior ledger, a changed-paths list, and optional verdicts.
  union   Join coverage units with a gap_analysis domain report by
          evidence-path overlap: hunt first where required controls are
          missing (must-build-gap) or flaws already fired (risk-observed).

Recon input shape (init --recon-json):
  {"surfaces": [{"surface": "POST /api/inquire",
                 "boundary": "unauthenticated", "subsystem": "api",
                 "paths": ["src/routes/inquire.py"],
                 "attack_classes": ["Injection"]  # optional; default scope
                }]}

The attack-class vocabulary mirrors the **Name** (subagent_type:) headings
in docs/security/attack-classes/ATTACK-CLASSES.md. Profiles change breadth,
never the evidence bar: quick scopes 4 high-yield classes, standard/deep
take all 9 (deep buys waves and attempts, not breadth).

Additive-run semantics (carry): covered+unchanged carries with its
evidence; covered+changed requeues to planned; candidates resolve through
the verdicts map (confirmed/rejected) else stay needs_validation; rejected
claims rescope to planned with a new prior_status instead of repeating;
deferred/blocked/out_of_scope carry forward as-is so a new run does not
re-spend their budget. Validators, not this module, own the schema.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_coverage_ledger as vcl

ALL_CLASSES = [
    "Injection",
    "Access control",
    "Resource and file handling",
    "Cryptography and secrets",
    "Business logic",
    "Feature abuse and data leakage",
    "Chained vulnerabilities and trust boundaries",
    "Wildcard",
    "Obvious things",
]

QUICK_CLASSES = [
    "Injection",
    "Access control",
    "Cryptography and secrets",
    "Chained vulnerabilities and trust boundaries",
]

PROFILES = {
    "quick": {"max_waves": 3, "max_attempts": 40, "reserve_waves": 1},
    "standard": {"max_waves": 4, "max_attempts": 120, "reserve_waves": 1},
    "deep": {"max_waves": 6, "max_attempts": 400, "reserve_waves": 1},
}

PROFILE_CLASSES = {"quick": QUICK_CLASSES, "standard": ALL_CLASSES,
                   "deep": ALL_CLASSES}

TERMINAL = {"covered", "candidate", "blocked", "deferred",
            "out_of_scope", "not_applicable"}


def _fail(msg: str) -> int:
    print(json.dumps({"error": msg}))
    return 2


def _load(path: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return exc


def cmd_init(args) -> int:
    recon = _load(args.recon_json)
    if isinstance(recon, Exception):
        return _fail("cannot read recon: %s" % recon)
    if args.profile not in PROFILES:
        return _fail("unknown profile: %s" % args.profile)
    scope = PROFILE_CLASSES[args.profile]
    surfaces = recon.get("surfaces", [])
    if not isinstance(surfaces, list) or not surfaces:
        return _fail("recon needs a non-empty 'surfaces' array")
    units = []
    for s in surfaces:
        if not isinstance(s, dict):
            return _fail("each surface must be an object")
        for key in ("surface", "boundary", "subsystem"):
            if not isinstance(s.get(key), str) or not s[key].strip():
                return _fail("surface needs non-blank '%s'" % key)
        classes = s.get("attack_classes") or scope
        for cls in classes:
            if cls not in ALL_CLASSES:
                return _fail("unknown attack_class: %r "
                             "(vocabulary mirrors ATTACK-CLASSES.md)" % cls)
            refs = {"surface": s["surface"], "boundary": s["boundary"],
                    "subsystem": s["subsystem"], "attack_class": cls}
            paths = s.get("paths") or []
            units.append({
                "coverage_id": vcl.canonical_id(refs),
                "canonical_refs": refs,
                "surface": s["surface"], "boundary": s["boundary"],
                "subsystem": s["subsystem"], "attack_class": cls,
                "starting_paths": list(paths),
                "ordinary_attack_class_block": "",
                "selected_companion_blocks": [],
                "excluded_blocks": [],
                "prior_status": "new",
                "attempts": [], "wave": 0, "status": "planned",
                "agent_id": "", "reviewed_paths": [], "local_checks": [],
                "result_fingerprints": [], "unresolved": "",
            })
    ids = [u["coverage_id"] for u in units]
    if len(set(ids)) != len(ids):
        return _fail("recon yields duplicate units; split surfaces further")
    Path(args.out).write_text(json.dumps(units, indent=2), encoding="utf-8")
    print(json.dumps({"units": len(units), "out": args.out}))
    return 0


def _critic_gaps(units: list) -> list:
    gaps = []
    for u in units:
        cid = u.get("coverage_id", "?")
        status = u.get("status")
        attempts = u.get("attempts") or []
        if status == "candidate" and not u.get("result_fingerprints"):
            gaps.append({"coverage_id": cid,
                         "issue": "candidate-without-evidence",
                         "suggestion": "attach result_fingerprints or "
                                       "demote to planned"})
        elif status in ("deferred", "blocked") and not u.get("unresolved"):
            gaps.append({"coverage_id": cid,
                         "issue": "terminal-without-reason",
                         "suggestion": "record the reason in unresolved"})
        elif status == "covered" and not attempts and not (
                u.get("reviewed_paths") or u.get("local_checks")):
            gaps.append({"coverage_id": cid,
                         "issue": "unsubstantiated-coverage",
                         "suggestion": "covered needs an attempt, reviewed "
                                       "paths, or local checks"})
        elif status in ("planned", "in_progress") and not attempts:
            gaps.append({"coverage_id": cid, "issue": "unworked",
                         "suggestion": "assign a hunter wave"})
    return gaps


def cmd_critic(args) -> int:
    units = _load(args.ledger)
    if isinstance(units, Exception):
        return _fail("cannot read ledger: %s" % units)
    if not isinstance(units, list):
        return _fail("ledger must be a top-level array of units")
    gaps = _critic_gaps(units)
    counts: dict = {}
    for g in gaps:
        counts[g["issue"]] = counts.get(g["issue"], 0) + 1
    report = {"units": len(units), "gaps": gaps,
              "unworked": counts.get("unworked", 0),
              "unsubstantiated": counts.get("unsubstantiated-coverage", 0),
              "issues": counts}
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        for g in gaps:
            print("%s [%s]: %s" % (g["coverage_id"], g["issue"],
                                   g["suggestion"]))
        print("%d units, %d gaps" % (len(units), len(gaps)))
    return 0


def cmd_budget(args) -> int:
    units = _load(args.ledger)
    if isinstance(units, Exception):
        return _fail("cannot read ledger: %s" % units)
    if args.profile not in PROFILES:
        return _fail("unknown profile: %s" % args.profile)
    limits = PROFILES[args.profile]
    touched = [u for u in units
               if (u.get("attempts") or u.get("status") != "planned")]
    attempts = sum(len(u.get("attempts") or []) for u in units)
    waves = (max([u.get("wave", 0) for u in units] + [0]) + 1)
    reserve_ok = (waves + limits["reserve_waves"] <= limits["max_waves"]
                  and attempts <= limits["max_attempts"])
    report = {"profile": args.profile, "limits": limits,
              "used": {"units_touched": len(touched),
                       "attempts": attempts, "waves": waves},
              "reserve_ok": reserve_ok}
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print("profile %s: %d units, %d attempts, %d waves "
              "(reserve %s)" % (args.profile, len(touched), attempts,
                                 waves, "ok" if reserve_ok else "EXHAUSTED"))
    return 0


def _changed(unit: dict, changed_paths: set, changed_subs: set) -> bool:
    paths = set(unit.get("starting_paths") or []) | set(
        unit.get("reviewed_paths") or [])
    return bool(paths & changed_paths) or unit.get("subsystem") in changed_subs


def cmd_carry(args) -> int:
    prior = _load(args.prior)
    ledger = _load(args.ledger)
    changed = _load(args.changed)
    if isinstance(prior, Exception):
        return _fail("cannot read prior: %s" % prior)
    if isinstance(ledger, Exception):
        return _fail("cannot read ledger: %s" % ledger)
    if isinstance(changed, Exception):
        return _fail("cannot read changed: %s" % changed)
    verdicts = {}
    if args.verdicts:
        verdicts = _load(args.verdicts)
        if isinstance(verdicts, Exception):
            return _fail("cannot read verdicts: %s" % verdicts)
    changed_paths = set(changed.get("changed_paths", []))
    changed_subs = set(changed.get("changed_subsystems", []))
    by_id = {u.get("coverage_id"): u for u in prior
             if isinstance(u, dict)}
    out = []
    for u in ledger:
        if not isinstance(u, dict):
            return _fail("ledger units must be objects")
        cid = u.get("coverage_id")
        p = by_id.get(cid)
        if p is None:
            u["prior_status"] = "new"
            out.append(u)
            continue
        p_status = p.get("status")
        moved = _changed(p, changed_paths, changed_subs)
        fps = p.get("result_fingerprints") or []
        confirmed = any(verdicts.get(f) == "confirmed" for f in fps)
        rejected = fps and all(verdicts.get(f) == "rejected" for f in fps)
        if p_status == "covered" and not moved:
            u["prior_status"] = "prior_covered_same_source"
            u["status"] = "covered"
            u["attempts"] = p.get("attempts", [])
            u["reviewed_paths"] = p.get("reviewed_paths", [])
            u["local_checks"] = p.get("local_checks", [])
            u["result_fingerprints"] = list(fps)
            u["agent_id"] = p.get("agent_id", "")
        elif p_status == "covered":
            u["prior_status"] = "prior_covered_changed_source"
            u["status"] = "planned"
        elif p_status == "candidate" and confirmed:
            u["prior_status"] = ("prior_confirmed_same_source" if not moved
                                 else "prior_confirmed_changed_source")
            u["status"] = "candidate"
            u["result_fingerprints"] = list(fps)
        elif p_status == "candidate" and rejected:
            u["prior_status"] = "prior_rejected_claim_changed"
            u["status"] = "planned"
            u["unresolved"] = ("prior claim rejected; vary the approach, "
                               "do not repeat it")
        elif p_status == "candidate":
            u["prior_status"] = "prior_needs_validation"
            u["status"] = "candidate"
            u["result_fingerprints"] = list(fps)
        elif p_status in ("deferred", "blocked", "out_of_scope"):
            u["prior_status"] = "prior_%s" % p_status
            u["status"] = p_status
            u["unresolved"] = p.get("unresolved", "")
        else:
            u["prior_status"] = "new"
            u["status"] = "planned"
        out.append(u)
    Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({"units": len(out), "out": args.out}))
    return 0


def cmd_union(args) -> int:
    units = _load(args.ledger)
    gap = _load(args.gap_report)
    if isinstance(units, Exception):
        return _fail("cannot read ledger: %s" % units)
    if isinstance(gap, Exception):
        return _fail("cannot read gap report: %s" % gap)
    caps = gap.get("capabilities", []) if isinstance(gap, dict) else []
    rows = []
    for u in units:
        if not isinstance(u, dict):
            return _fail("ledger units must be objects")
        upaths = set(u.get("starting_paths") or []) | set(
            u.get("reviewed_paths") or [])
        hits = [c for c in caps
                if set(c.get("evidence_files") or []) & upaths]
        if any(c.get("status") == "risk-observed" for c in hits):
            posture = "risk-observed"
        elif any(c.get("status") == "must-build gap" for c in hits):
            posture = "must-build-gap"
        elif hits:
            posture = "controls-present"
        else:
            posture = "unprofiled"
        rows.append({"coverage_id": u.get("coverage_id"),
                     "control_posture": posture,
                     "overlapping_caps": [c.get("id") for c in hits]})
    counts: dict = {}
    for r in rows:
        counts[r["control_posture"]] = counts.get(r["control_posture"], 0) + 1
    report = {"units": rows, "summary": counts}
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        for r in rows:
            print("%s: %s" % (r["coverage_id"], r["control_posture"]))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic coverage-hunting support (R-139).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="Partition recon into coverage units")
    p.add_argument("--recon-json", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--profile", default="standard",
                   choices=list(PROFILES))
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("critic", help="List uncovered/unsubstantiated units")
    p.add_argument("--ledger", required=True)
    p.add_argument("--format", default="table", choices=["table", "json"])
    p.set_defaults(fn=cmd_critic)
    p = sub.add_parser("budget", help="Account waves/attempts vs a profile")
    p.add_argument("--ledger", required=True)
    p.add_argument("--profile", default="standard", choices=list(PROFILES))
    p.add_argument("--format", default="table", choices=["table", "json"])
    p.set_defaults(fn=cmd_budget)
    p = sub.add_parser("carry", help="Stamp prior_status onto a fresh ledger")
    p.add_argument("--prior", required=True)
    p.add_argument("--ledger", required=True)
    p.add_argument("--changed", required=True,
                   help="JSON with changed_paths[] + changed_subsystems[]")
    p.add_argument("--verdicts", default="",
                   help="optional fingerprint->verdict JSON map")
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_carry)
    p = sub.add_parser("union",
                       help="Join coverage units with a gap_analysis report")
    p.add_argument("--ledger", required=True)
    p.add_argument("--gap-report", required=True)
    p.add_argument("--format", default="table", choices=["table", "json"])
    p.set_defaults(fn=cmd_union)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
