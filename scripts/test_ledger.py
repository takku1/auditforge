"""Tests for ledger.py - cross-run finding lifecycle (open/resolved/reopen)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ledger


@pytest.fixture()
def db(tmp_path):
    return str(tmp_path / "ledger.db")


def _report(*fps):
    return {"findings": [
        {"fingerprint": fp, "rule_id": "SEC001", "severity": "CRITICAL",
         "file": "a.py", "line": 1, "snippet": "s", "frameworks": []}
        for fp in fps]}


def _ingest(db, repo, run, findings):
    p = Path(db).parent / f"{run}.json"
    p.write_text(json.dumps(findings), encoding="utf-8")
    rc = ledger.main(["--db", db, "ingest", "--repo", repo,
                      "--run-id", run, "--audit-json", str(p)])
    assert rc == 0


def test_ingest_new_then_resolve_on_absence(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1", "fp2"))
    out = json.loads(capsys.readouterr().out)
    assert out == {"repo": "shop", "run_id": "r1", "new": 2, "reopened": 0,
                   "resolved": 0, "demoted": 0, "still_open": 2}
    capsys.readouterr()
    _ingest(db, "shop", "r2", _report("fp1"))
    out = json.loads(capsys.readouterr().out)
    assert out["new"] == 0 and out["resolved"] == 1 and out["still_open"] == 1


def test_resolved_finding_reopens(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1"))
    _ingest(db, "shop", "r2", _report())
    capsys.readouterr()
    _ingest(db, "shop", "r3", _report("fp1"))
    out = json.loads(capsys.readouterr().out)
    assert out["reopened"] == 1 and out["still_open"] == 1


def test_manual_resolve_and_stats(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1", "fp2"))
    capsys.readouterr()
    assert ledger.main(["--db", db, "resolve", "--repo", "shop",
                        "--fingerprint", "fp1", "--run-id", "r1b"]) == 0
    capsys.readouterr()
    assert ledger.main(["--db", db, "stats", "--repo", "shop"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["by_status"] == {"open": 1, "resolved": 1}
    assert stats["runs"] == 1


def test_verdict_lifecycle(db, capsys):
    # v2 step 1: deterministic findings enter unreviewed; a verification
    # verdict sticks; re-ingest without verdicts preserves it (additive).
    # R-137: confirmed needs an independent verifier plus evidence.
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    assert ledger.main(["--db", db, "verdict", "--repo", "shop",
                        "--fingerprint", "fp1", "--verdict", "confirmed",
                        "--run-id", "v1", "--reason", "repro passes",
                        "--verifier", "reviewer-1",
                        "--evidence", "poc artifact: /out/repro.log"]) == 0
    capsys.readouterr()
    _ingest(db, "shop", "r2", _report("fp1"))
    capsys.readouterr()
    assert ledger.main(["--db", db, "list", "--repo", "shop",
                        "--verdict", "confirmed", "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1 and rows[0]["verdict"] == "confirmed"
    assert rows[0]["verdict_reason"] == "repro passes"


def test_ingest_carries_item_verdict(db, capsys):
    # A verification run's findings.json already carries verdicts.
    rec = _report("fp9")["findings"][0]
    rec["verdict"] = "needs_validation"
    rec["blockers"] = ["need prod config"]
    _ingest(db, "shop", "r1", {"findings": [rec]})
    capsys.readouterr()
    assert ledger.main(["--db", db, "list", "--repo", "shop",
                        "--verdict", "needs_validation",
                        "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1 and rows[0]["fingerprint"] == "fp9"


def test_verdict_rejects_bad_value(db):
    with pytest.raises(SystemExit):
        ledger.main(["--db", db, "verdict", "--repo", "shop",
                     "--fingerprint", "fp1", "--verdict", "maybe",
                     "--run-id", "v1"])


def _confirm(db, fp, verifier="reviewer-1", evidence="poc:/out/r.log",
             reason="repro passes", run="v1"):
    return ledger.main(["--db", db, "verdict", "--repo", "shop",
                        "--fingerprint", fp, "--verdict", "confirmed",
                        "--run-id", run, "--reason", reason,
                        "--verifier", verifier, "--evidence", evidence])


def test_verdict_rejects_self_verification(db, capsys):
    # R-137: the finder is never the checker. Scanner-originated
    # candidates carry finder=deterministic-sweep by default.
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    rc = ledger.main(["--db", db, "verdict", "--repo", "shop",
                      "--fingerprint", "fp1", "--verdict", "confirmed",
                      "--run-id", "v1", "--reason", "trust me",
                      "--verifier", "deterministic-sweep",
                      "--evidence", "poc:/out/r.log"])
    assert rc == 3
    conn = __import__("sqlite3").connect(db)
    try:
        (v,) = conn.execute(
            "SELECT verdict FROM findings WHERE repo='shop' "
            "AND fingerprint='fp1'").fetchone()
        n = conn.execute("SELECT COUNT(*) FROM transitions").fetchone()[0]
    finally:
        conn.close()
    assert v == "unreviewed" and n == 0


def test_verdict_confirmed_requires_evidence(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    rc = ledger.main(["--db", db, "verdict", "--repo", "shop",
                      "--fingerprint", "fp1", "--verdict", "confirmed",
                      "--run-id", "v1", "--reason", "repro passes",
                      "--verifier", "reviewer-1", "--evidence", ""])
    assert rc == 3


def test_verdict_rejected_requires_disproof(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    rc = ledger.main(["--db", db, "verdict", "--repo", "shop",
                      "--fingerprint", "fp1", "--verdict", "rejected",
                      "--run-id", "v1", "--reason", "",
                      "--verifier", "reviewer-1"])
    assert rc == 3
    assert ledger.main(["--db", db, "verdict", "--repo", "shop",
                        "--fingerprint", "fp1", "--verdict", "rejected",
                        "--run-id", "v1", "--reason", "sink unreachable: auth gate",
                        "--verifier", "reviewer-1"]) == 0


def test_verdict_needs_validation_requires_blocker(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    rc = ledger.main(["--db", db, "verdict", "--repo", "shop",
                      "--fingerprint", "fp1",
                      "--verdict", "needs_validation",
                      "--run-id", "v1", "--reason", "",
                      "--verifier", "reviewer-1"])
    assert rc == 3


def test_verdict_transition_logged(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    assert _confirm(db, "fp1") == 0
    capsys.readouterr()
    assert ledger.main(["--db", db, "transitions", "--repo", "shop",
                        "--fingerprint", "fp1", "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1
    t = rows[0]
    assert (t["from_verdict"], t["to_verdict"]) == ("unreviewed", "confirmed")
    assert t["actor"] == "reviewer-1" and len(t["evidence_hash"]) == 40


def test_material_change_demotes_confirmed(db, capsys):
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    assert _confirm(db, "fp1") == 0
    capsys.readouterr()
    changed = _report("fp1")["findings"][0]
    changed["snippet"] = "sanitized now"
    changed["line"] = 2
    _ingest(db, "shop", "r2", {"findings": [changed]})
    out = json.loads(capsys.readouterr().out)
    assert out.get("demoted") == 1
    assert ledger.main(["--db", db, "list", "--repo", "shop",
                        "--verdict", "needs_validation",
                        "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1 and "material change" in rows[0]["verdict_reason"]


def test_material_replacement_needs_new_verifier(db, capsys):
    # Same verifier may not move the goalposts on its own confirmation;
    # an independent verifier re-verifying with new evidence may.
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    assert _confirm(db, "fp1") == 0
    capsys.readouterr()
    rc = ledger.main(["--db", db, "verdict", "--repo", "shop",
                      "--fingerprint", "fp1", "--verdict", "confirmed",
                      "--run-id", "v2", "--reason", "repro passes harder",
                      "--verifier", "reviewer-1",
                      "--evidence", "poc:/out/r2.log"])
    assert rc == 3
    assert _confirm(db, "fp1", verifier="reviewer-2",
                    evidence="poc:/out/r2.log", run="v2") == 0


def test_legacy_db_gains_verdict_columns_and_transitions(db, capsys):
    import sqlite3 as _sq
    legacy = str(Path(db).parent / "legacy.db")
    conn = _sq.connect(legacy)
    conn.executescript(
        "CREATE TABLE findings (repo TEXT, fingerprint TEXT, rule_id TEXT, "
        "tool TEXT, name TEXT, severity TEXT, file TEXT, line INTEGER, "
        "snippet TEXT, frameworks TEXT, first_seen_run TEXT, "
        "last_seen_run TEXT, status TEXT, resolved_run TEXT, "
        "verdict TEXT, verdict_reason TEXT, verdict_run TEXT, "
        "updated_at TEXT, "
        "PRIMARY KEY (repo, fingerprint));"
        "CREATE TABLE runs (run_id TEXT PRIMARY KEY, repo TEXT, target TEXT,"
        " source TEXT, profile TEXT, started_at TEXT, finished_at TEXT);")
    conn.close()
    p = Path(db).parent / "r.json"
    p.write_text(json.dumps(_report("fp1")), encoding="utf-8")
    assert ledger.main(["--db", legacy, "ingest", "--repo", "shop",
                        "--run-id", "r1", "--audit-json", str(p)]) == 0
    conn = _sq.connect(legacy)
    try:
        cols = {r[1] for r in
                conn.execute("PRAGMA table_info(findings)").fetchall()}
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    finally:
        conn.close()
    assert {"finder", "evidence", "verdict", "verdict_reason",
            "verdict_run"} <= cols
    assert "transitions" in tables


def test_universal_findings_get_stable_fingerprint(db, capsys):
    uni = {"findings": [{"rule_id": "R1", "tool": "Semgrep", "name": "x",
                         "severity": "HIGH", "file": "a.js", "line": 3,
                         "snippet": "s", "frameworks": ["ASVS:V1.2.1"]}]}
    p = Path(db).parent / "u.json"
    p.write_text(json.dumps(uni), encoding="utf-8")
    assert ledger.main(["--db", db, "ingest", "--repo", "shop",
                        "--run-id", "u1", "--audit-json", str(p)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["new"] == 1
    assert ledger.main(["--db", db, "list", "--repo", "shop",
                        "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1 and len(rows[0]["fingerprint"]) == 16
