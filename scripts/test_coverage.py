"""Tests for coverage.py - R-139 deterministic coverage-hunting support.

init (partition recon into units), critic (deterministic gapfind), budget
(accounting vs profiles), carry (additive prior_status rules), union
(coverage x domain-control posture). No agents, no network - pure JSON.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import coverage as cov
import validate_coverage_ledger as vcl


def _recon():
    return {"surfaces": [
        {"surface": "POST /api/inquire", "boundary": "unauthenticated",
         "subsystem": "api", "paths": ["src/routes/inquire.py"],
         "attack_classes": ["Injection", "Access control"]},
        {"surface": "GET /admin", "boundary": "authenticated",
         "subsystem": "web", "paths": ["src/routes/admin.py"]},
    ]}


def _init_ledger(tmp_path, recon=None, profile="standard"):
    out = tmp_path / "coverage-ledger.json"
    rc = cov.main(["init", "--recon-json", _write(tmp_path, recon or _recon()),
                   "--out", str(out), "--profile", profile])
    assert rc == 0
    return json.loads(out.read_text(encoding="utf-8"))


def _write(tmp_path, obj, name="in.json"):
    p = tmp_path / name
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


def test_init_partitions_surfaces_by_class(tmp_path):
    units = _init_ledger(tmp_path)
    # 2-class surface + all-class surface (9 canonical classes).
    assert len(units) == 2 + 9
    ids = {u["coverage_id"] for u in units}
    assert len(ids) == len(units)
    assert vcl.validate_file(str(tmp_path / "coverage-ledger.json")) == []


def test_init_ids_are_canonical(tmp_path):
    units = _init_ledger(tmp_path)
    u = next(u for u in units
             if u["surface"] == "POST /api/inquire"
             and u["attack_class"] == "Injection")
    assert u["coverage_id"] == vcl.canonical_id(u["canonical_refs"])
    assert u["status"] == "planned" and u["prior_status"] == "new"
    assert u["wave"] == 0 and u["attempts"] == []


def test_init_rejects_unknown_class(tmp_path):
    bad = {"surfaces": [{"surface": "x", "boundary": "y", "subsystem": "z",
                         "attack_classes": ["Nope"]}]}
    out = tmp_path / "o.json"
    rc = cov.main(["init", "--recon-json", _write(tmp_path, bad),
                   "--out", str(out)])
    assert rc == 2


def test_critic_finds_unworked_units(tmp_path, capsys):
    units = _init_ledger(tmp_path)
    capsys.readouterr()
    # Simulate one worked unit: covered with a traced attempt.
    units[0]["status"] = "covered"
    units[0]["attempts"] = [{"status": "covered"}]
    units[0]["reviewed_paths"] = ["src/routes/inquire.py"]
    p = _write(tmp_path, units, "led.json")
    assert cov.main(["critic", "--ledger", p, "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["unworked"] == len(units) - 1
    assert all(g["issue"] == "unworked" for g in report["gaps"])
    assert report["unsubstantiated"] == 0


def test_critic_flags_unevidenced_and_unreasoned(tmp_path, capsys):
    units = _init_ledger(tmp_path)
    capsys.readouterr()
    units[0]["status"] = "candidate"  # no result_fingerprints
    units[1]["status"] = "deferred"  # no unresolved reason
    units[2]["status"] = "covered"  # no attempts, no trace
    p = _write(tmp_path, units, "led.json")
    assert cov.main(["critic", "--ledger", p, "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    issues = {g["coverage_id"]: g["issue"] for g in report["gaps"]}
    assert issues[units[0]["coverage_id"]] == "candidate-without-evidence"
    assert issues[units[1]["coverage_id"]] == "terminal-without-reason"
    assert issues[units[2]["coverage_id"]] == "unsubstantiated-coverage"


def test_budget_profiles_account_waves(tmp_path, capsys):
    units = _init_ledger(tmp_path)
    capsys.readouterr()
    for u in units[:3]:
        u["status"] = "covered"
        u["wave"] = 1
        u["attempts"] = [{"status": "covered"}]
    p = _write(tmp_path, units, "led.json")
    assert cov.main(["budget", "--ledger", p, "--profile", "quick",
                     "--format", "json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["profile"] == "quick"
    assert rep["used"]["units_touched"] == 3
    assert rep["used"]["attempts"] == 3
    assert rep["reserve_ok"] is True
    # Exhausting all waves leaves no reserve for critics + validation.
    for u in units:
        u["wave"] = 2
    p2 = _write(tmp_path, units, "led2.json")
    assert cov.main(["budget", "--ledger", p2, "--profile", "quick",
                     "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["reserve_ok"] is False


def test_carry_same_source_carries_coverage(tmp_path):
    units = _init_ledger(tmp_path)
    u = units[0]
    u["status"] = "covered"
    u["attempts"] = [{"status": "covered"}]
    u["reviewed_paths"] = ["src/routes/inquire.py"]
    prior = _write(tmp_path, units, "prior.json")
    changed = _write(tmp_path, {"changed_paths": [], "changed_subsystems": []},
                     "changed.json")
    out = tmp_path / "new.json"
    assert cov.main(["carry", "--prior", prior, "--ledger", prior,
                     "--changed", changed, "--out", str(out)]) == 0
    new = json.loads(out.read_text(encoding="utf-8"))
    carried = next(x for x in new if x["coverage_id"] == u["coverage_id"])
    assert carried["status"] == "covered"
    assert carried["prior_status"] == "prior_covered_same_source"
    assert vcl.validate_file(str(out)) == []


def test_carry_changed_source_requeues(tmp_path):
    units = _init_ledger(tmp_path)
    u = units[0]
    u["status"] = "covered"
    u["reviewed_paths"] = ["src/routes/inquire.py"]
    prior = _write(tmp_path, units, "prior.json")
    changed = _write(tmp_path,
                     {"changed_paths": ["src/routes/inquire.py"],
                      "changed_subsystems": []}, "changed.json")
    out = tmp_path / "new.json"
    assert cov.main(["carry", "--prior", prior, "--ledger", prior,
                     "--changed", changed, "--out", str(out)]) == 0
    new = json.loads(out.read_text(encoding="utf-8"))
    carried = next(x for x in new if x["coverage_id"] == u["coverage_id"])
    assert carried["status"] == "planned"
    assert carried["prior_status"] == "prior_covered_changed_source"


def test_carry_rejected_claim_rescoped(tmp_path):
    units = _init_ledger(tmp_path)
    u = units[0]
    u["status"] = "candidate"
    u["result_fingerprints"] = ["fp-dead"]
    prior = _write(tmp_path, units, "prior.json")
    changed = _write(tmp_path, {"changed_paths": [], "changed_subsystems": []},
                     "changed.json")
    verdicts = _write(tmp_path, {"fp-dead": "rejected"}, "verdicts.json")
    out = tmp_path / "new.json"
    assert cov.main(["carry", "--prior", prior, "--ledger", prior,
                     "--changed", changed, "--verdicts", verdicts,
                     "--out", str(out)]) == 0
    new = json.loads(out.read_text(encoding="utf-8"))
    carried = next(x for x in new if x["coverage_id"] == u["coverage_id"])
    assert carried["prior_status"] == "prior_rejected_claim_changed"
    assert carried["status"] == "planned"


def test_union_flags_missing_controls(tmp_path, capsys):
    units = _init_ledger(tmp_path)
    capsys.readouterr()
    gap = {"domain": "website", "capabilities": [
        {"id": "auth", "title": "Auth", "must": True,
         "status": "must-build gap", "evidence_files": ["src/routes/inquire.py"],
         "fired_rules": [], "citations": []},
        {"id": "log", "title": "Logging", "must": False,
         "status": "present", "evidence_files": ["src/routes/admin.py"],
         "fired_rules": [], "citations": []},
    ], "summary": {}, "unresolved_refs": []}
    assert cov.main(["union",
                     "--ledger", _write(tmp_path, units, "led.json"),
                     "--gap-report", _write(tmp_path, gap, "gap.json"),
                     "--format", "json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    by_id = {r["coverage_id"]: r["control_posture"] for r in rep["units"]}
    inquire = [v for u, v in by_id.items() if "inquire" in u]
    admin = [v for u, v in by_id.items() if "admin" in u]
    assert inquire and set(inquire) == {"must-build-gap"}
    assert admin and set(admin) == {"controls-present"}
    assert rep["summary"]["must-build-gap"] == len(inquire)
