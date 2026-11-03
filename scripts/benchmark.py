#!/usr/bin/env python3
"""Frozen benchmark infrastructure (ROADMAP R-141).

Measures vulnerability-finding ability, not codebase size. Protocol:
docs/current/benchmark-protocol.md. No detection rules change here.

Commands:
  run-scanner  headless scanner-only run against a manifest target
  record       ingest agent-run artifacts with execution metadata
  score        match a run against ground truth (fail-closed)
  scorecard    markdown metrics table over scored runs
  limitations  markdown report of what is missing/unmeasured/uncertain

Fail-closed throughout: unknown targets, revision drift, missing ground
truth, or incomplete metadata exit 2 with a reason instead of scoring
anyway. Discovery recall (candidates) and confirmed precision
(`confirmed` verdicts) are always reported separately: verification that
rejects weak candidates must read as precision gained, never recall lost.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LINE_WINDOW = 3


def _fail(msg: str) -> int:
    print(json.dumps({"error": msg}))
    return 2


def _load(path: str, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return exc


def _content_hash(root: str) -> str:
    h = hashlib.sha256()
    files = []
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            files.append(os.path.join(dirpath, n))
    for f in sorted(files):
        rel = os.path.relpath(f, root).replace(os.sep, "/")
        h.update(rel.encode())
        with open(f, "rb") as fh:
            h.update(fh.read())
    return h.hexdigest()[:16]


def _target_revision(path: str, kind: str = "local-fixture") -> str:
    # Local fixtures pin by content even when they live inside a git repo
    # (the repo SHA would silently cover fixture edits); clones pin by
    # their own HEAD.
    if kind != "clone":
        return "content:" + _content_hash(path)
    try:
        proc = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        proc = None
    if proc is not None and proc.returncode == 0 and proc.stdout.strip():
        return "git:" + proc.stdout.strip()
    return "content:" + _content_hash(path)


def _manifest(path: str):
    data = _load(path, "manifest")
    if isinstance(data, Exception):
        return data
    if not isinstance(data, dict) or data.get("version") != 1:
        return ValueError("manifest must be a version-1 object")
    return data


def cmd_run_scanner(args) -> int:
    man = _manifest(args.manifest)
    if isinstance(man, Exception):
        return _fail("cannot read manifest: %s" % man)
    tgt = (man.get("targets") or {}).get(args.target)
    if not isinstance(tgt, dict) or not tgt.get("path"):
        return _fail("unknown target: %r" % args.target)
    tpath = tgt["path"]
    if not os.path.isdir(tpath):
        return _fail("target path is not a directory: %s" % tpath)
    rev = _target_revision(tpath, tgt.get("kind", "local-fixture"))
    pinned = tgt.get("revision")
    if pinned and pinned != rev:
        return _fail("target revision drift: manifest pins %r, found %r"
                     % (pinned, rev))
    import time as _time
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    script = str(Path(__file__).resolve().parent / "audit_repo.py")
    start = _time.time()
    try:
        proc = subprocess.run(
            [sys.executable, script, tpath, "--json", "--min-severity",
             "LOW"], capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as exc:
        return _fail("scanner execution failed: %s" % exc)
    duration = round(_time.time() - start, 1)
    try:
        findings_doc = json.loads(proc.stdout)
    except ValueError:
        return _fail("scanner did not emit JSON (rc=%d, stderr=%.200s)"
                     % (proc.returncode, proc.stderr))
    (out / "findings.json").write_text(json.dumps(findings_doc, indent=2),
                                       encoding="utf-8")
    meta = {"config": "scanner-only", "target": args.target,
            "revision": rev, "tool": "audit_repo-native",
            "duration_s": duration}
    (out / "meta.json").write_text(json.dumps(meta, indent=2),
                                   encoding="utf-8")
    print(json.dumps({"recorded": str(out), "revision": rev}))
    return 0


def cmd_record(args) -> int:
    man = _manifest(args.manifest)
    if isinstance(man, Exception):
        return _fail("cannot read manifest: %s" % man)
    if args.target not in (man.get("targets") or {}):
        return _fail("unknown target: %r" % args.target)
    findings = _load(args.findings, "findings")
    if isinstance(findings, Exception):
        return _fail("cannot read findings: %s" % findings)
    meta = _load(args.meta, "meta")
    if isinstance(meta, Exception):
        return _fail("cannot read meta: %s" % meta)
    if not isinstance(meta, dict):
        return _fail("meta must be an object")
    missing = [k for k in ("config", "target", "revision", "duration_s")
               if k not in meta]
    if missing:
        return _fail("incomplete execution metadata, missing: %s"
                     % ", ".join(missing))
    if meta.get("target") != args.target or meta.get("config") != args.config:
        return _fail("meta target/config disagree with CLI arguments")
    if args.config in ("scanner-hunter", "full-lifecycle"):
        for k in ("model", "prompts_hash", "budget_declared_s",
                  "tokens_used"):
            if k not in meta:
                return _fail("agent config %r needs execution metadata: %s"
                             % (args.config, k))
    if args.config == "full-lifecycle" and not args.ledger:
        return _fail("full-lifecycle record needs --ledger (verdict chain)")
    if args.ledger and not os.path.exists(args.ledger):
        return _fail("ledger not found: %s" % args.ledger)
    if args.coverage:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import validate_coverage_ledger as vcl
        errs = vcl.validate_file(args.coverage)
        if errs:
            return _fail("coverage ledger invalid: %s" % errs[0])
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(
        json.dumps(findings, indent=2), encoding="utf-8")
    for label, src in (("ledger", args.ledger), ("coverage", args.coverage)):
        if src:
            data = Path(src).read_bytes()
            (out / ("%s.input" % label)).write_bytes(data)
    run = dict(meta)
    run["recorded"] = True
    (out / "run.json").write_text(json.dumps(run, indent=2),
                                  encoding="utf-8")
    print(json.dumps({"recorded": str(out)}))
    return 0


def _finding_cwes(f: dict) -> set:
    cwes = set()
    for ref in f.get("soc2_controls", []) or []:
        if isinstance(ref, str) and ref.startswith("CWE-"):
            cwes.add(ref.split(":")[0].split()[0])
    return cwes


def _matches(f: dict, v: dict) -> bool:
    if os.path.basename(f.get("file", "")) != os.path.basename(v["file"]):
        return False
    try:
        if abs(int(f.get("line", -1)) - int(v["line"])) > LINE_WINDOW:
            return False
    except (TypeError, ValueError):
        return False
    if f.get("rule_id") == v.get("rule"):
        return True
    vcwe = v.get("cwe")
    return bool(vcwe) and vcwe in _finding_cwes(f)


def cmd_score(args) -> int:
    run = Path(args.run)
    try:
        findings = json.loads((run / "findings.json").read_text(
            encoding="utf-8"))["findings"]
        meta = json.loads((run / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, KeyError) as exc:
        return _fail("unreadable run dir: %s" % exc)
    gt = _load(args.ground_truth, "ground truth")
    if isinstance(gt, Exception):
        return _fail("cannot read ground truth: %s" % gt)
    if meta.get("revision") != gt.get("revision"):
        return _fail("revision drift: run %r vs ground truth %r "
                     "(stale labels refuse to score)"
                     % (meta.get("revision"), gt.get("revision")))
    vulns = gt.get("vulns", [])
    safes = gt.get("safe", [])
    seen = set()
    unique = []
    for f in findings:
        key = (f.get("rule_id"), os.path.basename(f.get("file", "")),
               f.get("line"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique
    # Nearest-wins assignment: adjacent vulns share match windows, so
    # greedy first-match would starve neighbors. Each finding claims its
    # nearest vuln (rule equality breaks ties); each vuln is claimed once.
    pairs = []
    for fi, f in enumerate(findings):
        for v in vulns:
            if _matches(f, v):
                try:
                    dist = abs(int(f.get("line", -10**9)) - int(v["line"]))
                except (TypeError, ValueError):
                    continue
                tie = 0 if f.get("rule_id") == v.get("rule") else 1
                pairs.append((dist, tie, fi, v["id"]))
    pairs.sort()
    used_f, used_v = set(), set()
    for _d, _t, fi, vid in pairs:
        if fi not in used_f and vid not in used_v:
            used_f.add(fi)
            used_v.add(vid)
    matched_v = used_v
    fps = [f for fi, f in enumerate(findings) if fi not in used_f]
    tp = len(matched_v)
    verdicts = {f.get("verdict", "unreviewed") for f in findings}
    located_v = set()
    for v in vulns:
        for f in findings:
            try:
                same = (os.path.basename(f.get("file", "")) ==
                        os.path.basename(v["file"]))
                close = abs(int(f.get("line", -10**9)) - int(v["line"]))
            except (TypeError, ValueError):
                continue
            if same and close <= LINE_WINDOW:
                located_v.add(v["id"])
                break
    misclassified = sorted(located_v - matched_v)
    fn = len(vulns) - tp
    fp = len(fps)
    safe_violated = []
    for s in safes:
        window = [f for f in findings
                  if os.path.basename(f.get("file", "")) ==
                  os.path.basename(s["file"])
                  and abs(int(f.get("line", -10**9)) - int(s["line"]))
                  <= LINE_WINDOW]
        if window:
            safe_violated.append(s["id"])
    safe_clean = len(safes) - len(safe_violated)
    precision = tp / (tp + fp) if (tp + fp) else 1.0 if not vulns else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    tnr = (safe_clean / len(safes)) if safes else None
    youden = (recall + tnr - 1) if tnr is not None else None
    confirmed = [f for f in findings if f.get("verdict") == "confirmed"]
    c_tp = sum(1 for v in vulns
               if any(_matches(f, v) for f in confirmed))
    c_fp = len(confirmed) - sum(
        1 for f in confirmed
        if any(_matches(f, v) for v in vulns))
    metrics = {
        "config": meta.get("config"), "target": meta.get("target"),
        "revision": meta.get("revision"),
        "verdicts_present": sorted(verdicts),
        "tp": tp, "fn": fn, "fp": fp,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if (precision + recall) else 0.0,
        "located": len(located_v),
        "misclassified": misclassified,
        "safe_total": len(safes), "safe_clean": safe_clean,
        "safe_violated": safe_violated,
        "tn_basis": "safe-sample" if safes else "none",
        "youdens_j_safe_sample": round(youden, 4)
        if youden is not None else None,
        "confirmed_tp": c_tp, "confirmed_fp": c_fp,
        "confirmed_precision": round(c_tp / (c_tp + c_fp), 4)
        if (c_tp + c_fp) else None,
        "unmatched_findings": [
            {"rule_id": f.get("rule_id"), "file": f.get("file"),
             "line": f.get("line")} for f in fps],
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2),
                                      encoding="utf-8")
    print(json.dumps({"tp": tp, "fn": fn, "fp": fp}))
    return 0


def cmd_scorecard(args) -> int:
    rows = []
    for res in args.results:
        try:
            m = json.loads((Path(res) / "metrics.json").read_text(
                encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _fail("unreadable scored result %s: %s" % (res, exc))
        rows.append(m)
    lines = ["# Benchmark scorecard", "",
             "| config | target | TP | FN | FP | precision | recall | F1 | "
             "confirmed precision |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for m in rows:
        lines.append("| %s | %s | %d | %d | %d | %.4f | %.4f | %.4f | %s |"
                     % (m.get("config"), m.get("target"), m["tp"],
                        m["fn"], m["fp"], m["precision"], m["recall"],
                        m["f1"], m.get("confirmed_precision")))
    lines += ["",
              "Discovery recall counts candidates; confirmed precision "
              "counts `confirmed` verdicts only. Youden's J (safe-sample) "
              "and safe-abstention counts are in metrics.json.",
              "See limitations.md: validator-clean and passing tests do "
              "not establish detection accuracy."]
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"scorecard": args.out, "runs": len(rows)}))
    return 0


def cmd_limitations(args) -> int:
    rows = []
    for res in args.results:
        try:
            m = json.loads((Path(res) / "metrics.json").read_text(
                encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return _fail("unreadable scored result %s: %s" % (res, exc))
        rows.append(m)
    lines = ["# Limitations", "",
             "What this scorecard does not establish:", "",
             "- Validator-clean ledgers and passing unit tests demonstrate "
             "regression health, not vulnerability-detection accuracy.",
             "- Youden's J is computed on the small labeled safe sample, "
             "never as a population claim.",
             "- Repeated samples of one case are not independent tasks; "
             "sample sizes are as reported in metrics.json.",
             "- Stub-backed sandbox tests prove lifecycle wiring, not "
             "container isolation; live Docker validation is outstanding.",
             "- Held-out results are valid only if no tuning was informed "
             "by held-out cases after the seal."]
    for m in rows:
        lines.append("- %s/%s: TP=%d FN=%d FP=%d, verdicts seen=%s"
                     % (m.get("config"), m.get("target"), m["tp"],
                        m["fn"], m["fp"],
                        ",".join(m.get("verdicts_present", []))))
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"limitations": args.out}))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Frozen benchmark infrastructure (R-141).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run-scanner", help="headless scanner-only run")
    p.add_argument("--manifest", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_run_scanner)
    p = sub.add_parser("record", help="ingest agent-run artifacts")
    p.add_argument("--manifest", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--config", required=True,
                   choices=["scanner-only", "scanner-hunter",
                            "full-lifecycle"])
    p.add_argument("--findings", required=True)
    p.add_argument("--ledger", default="")
    p.add_argument("--coverage", default="")
    p.add_argument("--meta", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_record)
    p = sub.add_parser("score", help="match a run against ground truth")
    p.add_argument("--run", required=True)
    p.add_argument("--ground-truth", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_score)
    p = sub.add_parser("scorecard", help="markdown metrics table")
    p.add_argument("--results", nargs="+", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_scorecard)
    p = sub.add_parser("limitations", help="limitations report")
    p.add_argument("--results", nargs="+", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_limitations)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
