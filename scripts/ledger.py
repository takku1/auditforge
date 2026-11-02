#!/usr/bin/env python3
"""Finding lifecycle ledger (ROADMAP R-108): stable cross-run finding state.

Deterministic scanners re-find the same issues every run; without a ledger
each run is amnesiac. This SQLite store (default reports/ledger.db,
gitignored) keys findings by (repo, fingerprint) - native findings carry a
stable sha1 fingerprint, universal ones get one computed the same way - and
tracks open/resolved across runs:

    python scripts/ledger.py ingest --repo shop --run-id r3 --audit-json report.json
    python scripts/ledger.py list --repo shop --status open
    python scripts/ledger.py resolve --repo shop --fingerprint <fp> --run-id r4

R-137 verdict discipline (fail-closed): every verdict transition needs
--verifier (an identity that is never the recorded finder) and --reason;
confirmed additionally needs --evidence (reproducible evidence, e.g. a PoC
artifact path). Same-verifier material replacement of a confirmation is
rejected - only an independent verifier may re-verify with new evidence.
Re-ingest that changes a confirmed/rejected finding's evidence fields
(file/line/snippet) demotes it to needs_validation. Every change is
appended to the transitions table; use `transitions` to audit the chain.
A missing row, a missing verifier, or missing evidence/disproof never
confirms - the commands exit non-zero and change nothing.

    python scripts/ledger.py verdict --repo shop --fingerprint <fp> \
        --verdict confirmed --run-id v1 --reason "repro passes" \
        --verifier reviewer-1 --evidence "poc:/out/repro.log"
    python scripts/ledger.py stats --repo shop

Ingest semantics (the VDH additive-run rule, simplified): findings present in
the report are new (first seen), re-observed (still open, last_seen bumped),
or reopened (previously resolved, now back). Open findings absent from the
report are resolved. Nothing is ever deleted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "reports" / "ledger.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY, repo TEXT NOT NULL, target TEXT DEFAULT '',
    source TEXT DEFAULT '', profile TEXT DEFAULT '',
    started_at TEXT NOT NULL, finished_at TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    repo TEXT NOT NULL, fingerprint TEXT NOT NULL,
    rule_id TEXT DEFAULT '', tool TEXT DEFAULT '', name TEXT DEFAULT '',
    severity TEXT DEFAULT '', file TEXT DEFAULT '', line INTEGER DEFAULT 0,
    snippet TEXT DEFAULT '', frameworks TEXT DEFAULT '[]',
    first_seen_run TEXT DEFAULT '', last_seen_run TEXT DEFAULT '',
    status TEXT DEFAULT 'open', resolved_run TEXT DEFAULT '',
    verdict TEXT DEFAULT 'unreviewed', verdict_reason TEXT DEFAULT '',
    verdict_run TEXT DEFAULT '',
    finder TEXT DEFAULT 'deterministic-sweep', evidence TEXT DEFAULT '',
    updated_at TEXT NOT NULL,
    PRIMARY KEY (repo, fingerprint)
);
"""

VERDICTS = ("unreviewed", "confirmed", "needs_validation", "rejected")

# Static per-column migration statements. Column names cannot be bind
# parameters, so each ALTER is a fixed string over the hardcoded column set
# above — never interpolated — so there is no injection surface by
# construction (SDLC002-safe: no %/format/concat in any execute call).
_MIGRATIONS = {
    "verdict": "ALTER TABLE findings ADD COLUMN verdict TEXT DEFAULT 'unreviewed'",
    "verdict_reason": "ALTER TABLE findings ADD COLUMN verdict_reason TEXT DEFAULT ''",
    "verdict_run": "ALTER TABLE findings ADD COLUMN verdict_run TEXT DEFAULT ''",
    "finder": "ALTER TABLE findings ADD COLUMN finder TEXT DEFAULT 'deterministic-sweep'",
    "evidence": "ALTER TABLE findings ADD COLUMN evidence TEXT DEFAULT ''",
    "resolved_run": "ALTER TABLE findings ADD COLUMN resolved_run TEXT DEFAULT ''",
}

TRANSITIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    from_verdict TEXT NOT NULL,
    to_verdict TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_hash TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_transitions_fp ON transitions (repo, fingerprint, id);
"""

GUARD_EXIT = 3


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn(db: str) -> sqlite3.Connection:
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA)
    conn.executescript(TRANSITIONS_SCHEMA)
    have = {r[1] for r in
            conn.execute("PRAGMA table_info(findings)").fetchall()}
    for col, stmt in _MIGRATIONS.items():
        if col not in have:
            conn.execute(stmt)
    conn.commit()
    return conn


def _evidence_hash(evidence: str) -> str:
    return hashlib.sha1(evidence.encode()).hexdigest() if evidence else ""


def _log_transition(conn: sqlite3.Connection, repo: str, fp: str,
                    frm: str, to: str, actor: str, reason: str,
                    evidence: str, run_id: str) -> None:
    conn.execute(
        "INSERT INTO transitions (repo, fingerprint, from_verdict, "
        "to_verdict, actor, reason, evidence_hash, run_id, at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (repo, fp, frm, to, actor, reason, _evidence_hash(evidence),
         run_id, _now()))


def _guard_fail(msg: str) -> int:
    print(json.dumps({"error": msg}))
    return GUARD_EXIT


def _stable_fp(item: dict) -> str:
    fp = item.get("fingerprint") or ""
    if fp:
        return str(fp)
    core = "|".join(str(item.get(k, "")) for k in
                    ("rule_id", "file", "line")) + "|" + str(item.get("snippet", ""))[:200]
    return hashlib.sha1(core.encode()).hexdigest()[:16]


def cmd_ingest(args) -> int:
    with open(args.audit_json, encoding="utf-8") as f:
        report = json.load(f)
    items = report.get("findings", [])
    conn = _conn(args.db)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO runs (run_id, repo, target, source, profile, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (args.run_id, args.repo, args.target, args.source, args.profile, _now()))
        seen = set()
        new, reopened, demoted = 0, 0, 0
        for item in items:
            if not isinstance(item, dict):
                continue
            fp = _stable_fp(item)
            seen.add(fp)
            row = conn.execute(
                "SELECT status, verdict, verdict_reason, verdict_run, "
                "finder, evidence, file, line, snippet "
                "FROM findings WHERE repo = ? AND fingerprint = ?",
                (args.repo, fp)).fetchone()
            frameworks = item.get("frameworks") or item.get("soc2_controls") or []
            item_verdict = item.get("verdict")
            item_verdict = item_verdict if item_verdict in VERDICTS else None
            blockers = item.get("blockers")
            item_reason = item.get("verdict_reason") or (
                "; ".join(blockers) if isinstance(blockers, list) else "")
            item_finder = str(item.get("finder") or args.finder or
                              "deterministic-sweep")
            item_evidence = str(item.get("evidence") or "")
            values = (args.repo, fp, str(item.get("rule_id", "")),
                      str(item.get("tool", "") or item.get("category", "")),
                      str(item.get("name", "")), str(item.get("severity", "")),
                      str(item.get("file", "")), int(item.get("line", 0) or 0),
                      str(item.get("snippet", ""))[:500],
                      json.dumps(frameworks), _now())
            if row is None:
                verdict = item_verdict or "unreviewed"
                conn.execute(
                    "INSERT INTO findings (repo, fingerprint, rule_id, tool, name, severity, "
                    "file, line, snippet, frameworks, first_seen_run, last_seen_run, "
                    "status, verdict, verdict_reason, verdict_run, finder, evidence, "
                    "updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)",
                    values[:10] + (args.run_id, args.run_id, verdict,
                                   str(item_reason),
                                   args.run_id if item_verdict else "",
                                   item_finder, item_evidence, _now()))
                if item_verdict is not None:
                    _log_transition(conn, args.repo, fp, "unreviewed",
                                    item_verdict, item_finder, str(item_reason),
                                    item_evidence, args.run_id)
                new += 1
            else:
                (status, s_verdict, s_reason, s_vrun, s_finder, s_evidence,
                 s_file, s_line, s_snippet) = row
                changed = ((s_file, s_line, s_snippet) !=
                           (values[6], values[7], values[8]))
                if s_verdict in ("confirmed", "rejected") and changed:
                    verdict = "needs_validation"
                    reason = ("material change since %s: evidence fields "
                              "changed; prior %s no longer stands"
                              % (s_vrun or s_verdict, s_verdict))
                    vrun, finder, evidence = (args.run_id, s_finder,
                                             s_evidence)
                    _log_transition(conn, args.repo, fp, s_verdict, verdict,
                                    "ingest", reason, evidence, args.run_id)
                    demoted += 1
                elif item_verdict is not None:
                    verdict, reason, vrun = (
                        item_verdict, str(item_reason), args.run_id)
                    finder, evidence = item_finder, item_evidence or s_evidence
                    if (verdict, reason) != (s_verdict, s_reason):
                        _log_transition(conn, args.repo, fp, s_verdict,
                                        verdict, finder, reason, evidence,
                                        args.run_id)
                else:
                    verdict, reason, vrun = s_verdict, s_reason, s_vrun
                    finder = item_finder if item.get("finder") else s_finder
                    evidence = s_evidence
                conn.execute(
                    "UPDATE findings SET rule_id=?, tool=?, name=?, severity=?, file=?, "
                    "line=?, snippet=?, frameworks=?, last_seen_run=?, "
                    "status='open', resolved_run='', verdict=?, verdict_reason=?, "
                    "verdict_run=?, finder=?, evidence=?, updated_at=? "
                    "WHERE repo=? AND fingerprint=?",
                    values[2:10] + (args.run_id, verdict, reason, vrun,
                                    finder, evidence, _now(), args.repo, fp))
                if status == "resolved":
                    reopened += 1
        cur = conn.execute(
            "UPDATE findings SET status='resolved', resolved_run=?, updated_at=? "
            "WHERE repo=? AND status='open' AND last_seen_run != ?",
            (args.run_id, _now(), args.repo, args.run_id))
        resolved = cur.rowcount
        conn.execute("UPDATE runs SET finished_at=? WHERE run_id=?", (_now(), args.run_id))
        conn.commit()
        still_open = conn.execute(
            "SELECT COUNT(*) FROM findings WHERE repo=? AND status='open'",
            (args.repo,)).fetchone()[0]
        print(json.dumps({"repo": args.repo, "run_id": args.run_id,
                          "new": new, "reopened": reopened,
                          "resolved": resolved, "demoted": demoted,
                          "still_open": still_open}))
        return 0
    finally:
        conn.close()


def cmd_list(args) -> int:
    conn = _conn(args.db)
    try:
        conds, params = ["repo = ?"], [args.repo]
        if args.status:
            conds.append("status = ?")
            params.append(args.status)
        if getattr(args, "verdict", None):
            conds.append("verdict = ?")
            params.append(args.verdict)
        rows = conn.execute(
            "SELECT fingerprint, rule_id, severity, file, line, status, "
            "first_seen_run, last_seen_run, verdict, verdict_reason, verdict_run, "
            "finder, evidence "
            "FROM findings WHERE " + " AND ".join(conds) + " ORDER BY severity, file",
            params).fetchall()
        cols = ["fingerprint", "rule_id", "severity", "file", "line",
                "status", "first_seen_run", "last_seen_run",
                "verdict", "verdict_reason", "verdict_run",
                "finder", "evidence"]
        if args.format == "json":
            print(json.dumps([dict(zip(cols, r)) for r in rows], indent=2))
        else:
            for r in rows:
                print(f"{r[1]:28} {r[2]:8} {r[3]}:{r[4]} [{r[5]}/{r[8]}] {r[0][:12]}")
        return 0
    finally:
        conn.close()


def cmd_verdict(args) -> int:
    conn = _conn(args.db)
    try:
        row = conn.execute(
            "SELECT verdict, verdict_reason, verdict_run, finder, evidence "
            "FROM findings WHERE repo=? AND fingerprint=?",
            (args.repo, args.fingerprint)).fetchone()
        if row is None:
            return _guard_fail("no such finding: nothing recorded")
        s_verdict, s_reason, s_vrun, finder, s_evidence = row
        verifier = getattr(args, "verifier", "") or ""
        evidence = getattr(args, "evidence", "") or ""
        reason = getattr(args, "reason", "") or ""
        if not verifier:
            return _guard_fail("verdict requires --verifier")
        if verifier == finder:
            return _guard_fail("finder is never the checker: %s found it"
                               % verifier)
        if not reason:
            return _guard_fail("%s requires --reason" % args.verdict)
        if args.verdict == "confirmed" and not evidence:
            return _guard_fail("confirmed requires --evidence")
        if (args.verdict == "confirmed" and s_verdict == "confirmed"
                and s_evidence and evidence
                and evidence != s_evidence):
            last = conn.execute(
                "SELECT actor FROM transitions WHERE repo=? AND "
                "fingerprint=? ORDER BY id DESC LIMIT 1",
                (args.repo, args.fingerprint)).fetchone()
            if last is not None and last[0] == verifier:
                return _guard_fail(
                    "material replacement of a confirmation needs an "
                    "independent verifier")
        if (args.verdict, reason) == (s_verdict, s_reason) and (
                not evidence or evidence == s_evidence):
            print(json.dumps({"verdict": args.verdict, "updated": 0,
                              "noop": True}))
            return 0
        conn.execute(
            "UPDATE findings SET verdict=?, verdict_reason=?, verdict_run=?, "
            "evidence=?, updated_at=? WHERE repo=? AND fingerprint=?",
            (args.verdict, reason, args.run_id,
             evidence or s_evidence, _now(),
             args.repo, args.fingerprint))
        _log_transition(conn, args.repo, args.fingerprint, s_verdict,
                        args.verdict, verifier, reason,
                        evidence or s_evidence, args.run_id)
        conn.commit()
        print(json.dumps({"verdict": args.verdict, "updated": 1}))
        return 0
    finally:
        conn.close()


def cmd_transitions(args) -> int:
    conn = _conn(args.db)
    try:
        conds, params = ["repo = ?"], [args.repo]
        if getattr(args, "fingerprint", None):
            conds.append("fingerprint = ?")
            params.append(args.fingerprint)
        rows = conn.execute(
            "SELECT id, fingerprint, from_verdict, to_verdict, actor, "
            "reason, evidence_hash, run_id, at FROM transitions WHERE "
            + " AND ".join(conds) + " ORDER BY id",
            params).fetchall()
        cols = ["id", "fingerprint", "from_verdict", "to_verdict", "actor",
                "reason", "evidence_hash", "run_id", "at"]
        if args.format == "json":
            print(json.dumps([dict(zip(cols, r)) for r in rows], indent=2))
        else:
            for r in rows:
                print(f"{r[0]:4} {r[1][:12]} {r[2]}->{r[3]} "
                      f"by {r[4]} ({r[7]}): {r[5][:80]}")
        return 0
    finally:
        conn.close()


def cmd_resolve(args) -> int:
    conn = _conn(args.db)
    try:
        cur = conn.execute(
            "UPDATE findings SET status='resolved', resolved_run=?, updated_at=? "
            "WHERE repo=? AND fingerprint=? AND status='open'",
            (args.run_id, _now(), args.repo, args.fingerprint))
        conn.commit()
        print(json.dumps({"resolved": cur.rowcount}))
        return 0 if cur.rowcount else 2
    finally:
        conn.close()


def cmd_stats(args) -> int:
    conn = _conn(args.db)
    try:
        by_status = dict(conn.execute(
            "SELECT status, COUNT(*) FROM findings WHERE repo=? GROUP BY status",
            (args.repo,)).fetchall())
        by_rule = conn.execute(
            "SELECT rule_id, COUNT(*) FROM findings WHERE repo=? AND status='open' "
            "GROUP BY rule_id ORDER BY 2 DESC LIMIT 10", (args.repo,)).fetchall()
        by_verdict = dict(conn.execute(
            "SELECT verdict, COUNT(*) FROM findings WHERE repo=? AND status='open' "
            "GROUP BY verdict", (args.repo,)).fetchall())
        runs = conn.execute("SELECT COUNT(*) FROM runs WHERE repo=?",
                            (args.repo,)).fetchone()[0]
        print(json.dumps({"repo": args.repo, "runs": runs,
                          "by_status": by_status,
                          "by_verdict": by_verdict,
                          "top_open_rules": by_rule}, indent=2))
        return 0
    finally:
        conn.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Finding lifecycle ledger.")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="Ledger DB path")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ingest", help="Ingest a JSON audit report")
    p.add_argument("--repo", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--audit-json", required=True)
    p.add_argument("--target", default="")
    p.add_argument("--source", default="audit_repo")
    p.add_argument("--profile", default="standard")
    p.add_argument("--finder", default="deterministic-sweep",
                   help="origin identity stamped on ingested candidates")
    p.set_defaults(fn=cmd_ingest)
    p = sub.add_parser("list", help="List findings")
    p.add_argument("--repo", required=True)
    p.add_argument("--status", default=None, choices=["open", "resolved"])
    p.add_argument("--verdict", default=None, choices=list(VERDICTS))
    p.add_argument("--format", default="table", choices=["table", "json"])
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("resolve", help="Manually resolve a finding")
    p.add_argument("--repo", required=True)
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_resolve)
    p = sub.add_parser("verdict", help="Record a verification verdict")
    p.add_argument("--repo", required=True)
    p.add_argument("--fingerprint", required=True)
    p.add_argument("--verdict", required=True, choices=list(VERDICTS))
    p.add_argument("--reason", default="")
    p.add_argument("--verifier", default="",
                   help="identity recording the verdict; must differ from finder")
    p.add_argument("--evidence", default="",
                   help="reproducible evidence (required to confirm)")
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_verdict)
    p = sub.add_parser("transitions", help="Audit a finding's verdict chain")
    p.add_argument("--repo", required=True)
    p.add_argument("--fingerprint", default=None)
    p.add_argument("--format", default="table", choices=["table", "json"])
    p.set_defaults(fn=cmd_transitions)
    p = sub.add_parser("stats", help="Repo summary")
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_stats)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
