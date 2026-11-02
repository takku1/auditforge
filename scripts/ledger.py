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
    python scripts/ledger.py verdict --repo shop --fingerprint <fp> \
        --verdict confirmed --run-id v1 --reason "repro passes"
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
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn(db: str) -> sqlite3.Connection:
    Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA)
    have = {r[1] for r in
            conn.execute("PRAGMA table_info(findings)").fetchall()}
    for col, stmt in _MIGRATIONS.items():
        if col not in have:
            conn.execute(stmt)
    conn.commit()
    return conn


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
        new, reopened = 0, 0
        for item in items:
            if not isinstance(item, dict):
                continue
            fp = _stable_fp(item)
            seen.add(fp)
            row = conn.execute(
                "SELECT status, verdict, verdict_reason, verdict_run "
                "FROM findings WHERE repo = ? AND fingerprint = ?",
                (args.repo, fp)).fetchone()
            frameworks = item.get("frameworks") or item.get("soc2_controls") or []
            item_verdict = item.get("verdict")
            item_verdict = item_verdict if item_verdict in VERDICTS else None
            blockers = item.get("blockers")
            item_reason = item.get("verdict_reason") or (
                "; ".join(blockers) if isinstance(blockers, list) else "")
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
                    "status, verdict, verdict_reason, verdict_run, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)",
                    values[:10] + (args.run_id, args.run_id, verdict,
                                   str(item_reason),
                                   args.run_id if item_verdict else "", _now()))
                new += 1
            else:
                if item_verdict is not None:
                    verdict, reason, vrun = (
                        item_verdict, str(item_reason), args.run_id)
                else:
                    verdict, reason, vrun = row[1], row[2], row[3]
                conn.execute(
                    "UPDATE findings SET rule_id=?, tool=?, name=?, severity=?, file=?, "
                    "line=?, snippet=?, frameworks=?, last_seen_run=?, "
                    "status='open', resolved_run='', verdict=?, verdict_reason=?, "
                    "verdict_run=?, updated_at=? "
                    "WHERE repo=? AND fingerprint=?",
                    values[2:10] + (args.run_id, verdict, reason, vrun,
                                    _now(), args.repo, fp))
                if row[0] == "resolved":
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
                          "resolved": resolved, "still_open": still_open}))
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
            "first_seen_run, last_seen_run, verdict, verdict_reason, verdict_run "
            "FROM findings WHERE " + " AND ".join(conds) + " ORDER BY severity, file",
            params).fetchall()
        cols = ["fingerprint", "rule_id", "severity", "file", "line",
                "status", "first_seen_run", "last_seen_run",
                "verdict", "verdict_reason", "verdict_run"]
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
        cur = conn.execute(
            "UPDATE findings SET verdict=?, verdict_reason=?, verdict_run=?, "
            "updated_at=? WHERE repo=? AND fingerprint=?",
            (args.verdict, args.reason, args.run_id, _now(),
             args.repo, args.fingerprint))
        conn.commit()
        print(json.dumps({"verdict": args.verdict,
                          "updated": cur.rowcount}))
        return 0 if cur.rowcount else 2
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
    p.add_argument("--run-id", required=True)
    p.set_defaults(fn=cmd_verdict)
    p = sub.add_parser("stats", help="Repo summary")
    p.add_argument("--repo", required=True)
    p.set_defaults(fn=cmd_stats)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
