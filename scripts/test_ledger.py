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
                   "resolved": 0, "still_open": 2}
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
    _ingest(db, "shop", "r1", _report("fp1"))
    capsys.readouterr()
    assert ledger.main(["--db", db, "verdict", "--repo", "shop",
                        "--fingerprint", "fp1", "--verdict", "confirmed",
                        "--run-id", "v1", "--reason", "repro passes"]) == 0
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
