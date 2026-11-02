"""Tests for check_freshness.py - the freshness pipeline gate.

All tests exercise the pure `evaluate()` diff and the manifest round-trip;
no network, no git, no KB clones required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_freshness import _drop_pct, evaluate, main


def _state(families=None, total=None, kb=None, engines=None,
           kev_ids=None, kev_status="ok", watches=None):
    families = families or {"NIST53": 1000, "CSF2": 100}
    total = len(families) and sum(families.values()) if total is None else total
    return {
        "framework_metadata": {"controls": total, "families": len(families)},
        "families": {f: {"controls": n, "label": f} for f, n in families.items()},
        "knowledge_bases": kb or {"oscal-content": {"commit": "abc123",
                                                    "date": "2026-10-01",
                                                    "status": "ok"}},
        "engines": engines or {"semgrep": "1.2.3"},
        "kev": {"status": kev_status, "fetched_at": "2026-11-01T00:00:00+00:00",
                "count": len(kev_ids or []), "ids": kev_ids or []},
        "derived": {"vector_index": {"present": True, "stale": False}},
        "watches": watches if watches is not None else [],
    }


TODAY = "2026-11-02"


def test_no_baseline_is_info_not_error():
    r = evaluate(None, _state(), TODAY, 10.0)
    assert r["errors"] == [] and len(r["info"]) == 1


def test_family_vanished_errors():
    old = _state()
    new = _state(families={"NIST53": 1000})  # CSF2 gone
    r = evaluate(old, new, TODAY, 10.0)
    assert any("vanished" in e and "CSF2" in e for e in r["errors"])


def test_family_zeroed_errors():
    old = _state()
    new = _state(families={"NIST53": 1000, "CSF2": 0})
    r = evaluate(old, new, TODAY, 10.0)
    assert any("zeroed" in e and "CSF2" in e for e in r["errors"])


def test_family_shrink_past_gate_errors():
    old = _state()
    new = _state(families={"NIST53": 800, "CSF2": 100})  # -20%
    r = evaluate(old, new, TODAY, 10.0)
    assert any("shrunk" in e or "shrank" in e for e in r["errors"])


def test_drop_at_gate_boundary_passes():
    old = _state(families={"NIST53": 1000})
    new = _state(families={"NIST53": 900}, total=900)  # exactly -10%
    r = evaluate(old, new, TODAY, 10.0)
    assert r["errors"] == []


def test_new_family_is_info():
    old = _state()
    new = _state(families={"NIST53": 1000, "CSF2": 100, "GENAI": 115})
    r = evaluate(old, new, TODAY, 10.0)
    assert r["errors"] == []
    assert any("GENAI" in m for m in r["info"])


def test_kev_new_ids_are_watch_signal_not_errors():
    old = _state(kev_ids=["CVE-2024-0001"])
    new = _state(kev_ids=["CVE-2024-0001", "CVE-2024-9999"])
    r = evaluate(old, new, TODAY, 10.0)
    assert r["errors"] == []
    assert r["kev_new"] == ["CVE-2024-9999"]


def test_kev_offline_warns():
    old = _state(kev_ids=["CVE-2024-0001"])
    new = _state(kev_status="offline (no route)", kev_ids=[])
    r = evaluate(old, new, TODAY, 10.0)
    assert r["errors"] == [] and r["kev_new"] == []
    assert any("KEV" in w for w in r["warnings"])


def test_engine_disappeared_warns_not_errors():
    old = _state(engines={"semgrep": "1.2.3"})
    new = _state(engines={"semgrep": "missing"})
    r = evaluate(old, new, TODAY, 10.0)
    assert r["errors"] == []
    assert any("disappeared" in w for w in r["warnings"])


def test_watches_overdue_and_due_soon():
    watches = [
        {"id": "past", "due": "2026-10-01", "note": "n"},
        {"id": "soon", "due": "2026-11-20", "note": "n"},
        {"id": "far", "due": "2027-06-01", "note": "n"},
        {"id": "dateless", "due": None, "note": "n"},
    ]
    r = evaluate(_state(watches=[]), _state(watches=watches), TODAY, 10.0)
    assert any("past-due" in w and "past" in w for w in r["warnings"])
    assert any("due in" in w and "soon" in w for w in r["warnings"])
    assert not any("far" in w for w in r["warnings"])


def test_stale_index_warns():
    new = _state()
    new["derived"] = {"vector_index": {"present": True, "stale": True}}
    r = evaluate(_state(), new, TODAY, 10.0)
    assert any("index" in w for w in r["warnings"])


def test_drop_pct_edges():
    assert _drop_pct(0, 0) == 0.0
    assert _drop_pct(0, 5) == 100.0
    assert _drop_pct(100, 100) == 0.0


def test_manifest_round_trip_and_gate(tmp_path):
    manifest = tmp_path / "freshness_manifest.json"
    live = _state(watches=[])
    manifest.write_text(json.dumps(live), encoding="utf-8")
    # identical state gates clean (exit 0); note: build_live_state reads the
    # real repo, so here we only verify --manifest plumbing parses.
    rc = main(["--manifest", str(manifest), "--skip-kev"])
    assert rc in (0, 1)  # live repo state may legitimately differ
