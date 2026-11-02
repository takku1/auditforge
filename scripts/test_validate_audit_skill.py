"""Tests for the findings/coverage-ledger validators (stdlib ports of the
Cloudflare skill's .cjs validators - no Node.js required)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_findings as vf
import validate_coverage_ledger as vc
import sync_skills


def _trace():
    return [
        {"kind": "entrypoint", "file": "api/submit.ts", "line": 4,
         "scope": "POST", "description": "in"},
        {"kind": "propagation", "file": "lib/db.ts", "line": 9,
         "scope": "save", "description": "through"},
        {"kind": "sink", "file": "lib/db.ts", "line": 12,
         "scope": "query", "description": "out"},
    ]


def _confirmed():
    return {
        "verdict": "confirmed", "fingerprint": "WEB/004/api/submit.ts",
        "title": "Missing rate limiting", "description": "No throttle.",
        "root_cause": "No limiter.", "intended_behavior": "429 after N.",
        "trace": _trace(),
        "evidence": [{"file": "a", "line": 1, "description": "saw it"}],
        "conditions": [],
        "execution": {"attacker_perspective": "anon", "payloads": ["x200"],
                      "instructions": ["send"], "observed_result": "200s"},
        "remediation": "Add limiter.",
        "severity": {"likelihood": {"score": "high", "reason": "anon"},
                     "impact": {"score": "medium",
                                "reason": "spam"},
                     "overall_severity": "medium"},
        "confidence": {"score": "high", "reason": "reproduced"},
    }


def _needs():
    return {
        "verdict": "needs_validation", "fingerprint": "X/1",
        "title": "Suspect sink", "description": "Maybe.",
        "claimed_root_cause": "Maybe unsanitized.",
        "trace": [_trace()[0]],
        "evidence": [{"file": "a", "line": 1, "description": "saw it"}],
        "blockers": ["need prod config"],
        "validation_plan": {"deployment": "check prod headers"},
    }


def _rejected():
    return {
        "verdict": "rejected", "fingerprint": "Y/2",
        "title": "Not a bug", "description": "Dead code.",
        "claimed_root_cause": "Looked like XSS.",
        "trace": [_trace()[2]],
        "evidence": [{"file": "a", "line": 1, "description": "unreachable"}],
        "reason": "Sink unreachable; caller sanitizes.",
    }


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


# findings ---------------------------------------------------------------

def test_valid_confirmed_passes(tmp_path):
    assert vf.validate_file(_write(tmp_path, "f.json", [_confirmed()])) == []


def test_valid_needs_and_rejected_pass(tmp_path):
    assert vf.validate_file(_write(tmp_path, "f.json",
                                   [_needs(), _rejected()])) == []


def test_bad_verdict_and_top_level(tmp_path):
    bad = dict(_confirmed())
    bad["verdict"] = "maybe"
    assert vf.validate_file(_write(tmp_path, "f.json", [bad]))
    assert vf.validate_file(_write(tmp_path, "g.json",
                                   {"verdict": "confirmed"}))


def test_severity_on_needs_is_rejected(tmp_path):
    rec = _needs()
    rec["severity"] = "high"
    errors = vf.validate_file(_write(tmp_path, "f.json", [rec]))
    assert any("must not use 'severity'" in e for e in errors)


def test_overall_above_impact_fails(tmp_path):
    rec = _confirmed()
    rec["severity"]["overall_severity"] = "critical"
    errors = vf.validate_file(_write(tmp_path, "f.json", [rec]))
    assert any("exceeds demonstrated impact" in e for e in errors)


def test_trace_must_start_with_entrypoint(tmp_path):
    rec = _confirmed()
    rec["trace"] = list(reversed(rec["trace"]))
    errors = vf.validate_file(_write(tmp_path, "f.json", [rec]))
    assert any("start with entrypoint" in e for e in errors)


def test_blockers_required(tmp_path):
    rec = _needs()
    rec["blockers"] = []
    errors = vf.validate_file(_write(tmp_path, "f.json", [rec]))
    assert any("blockers" in e for e in errors)


def test_extra_keys_rejected(tmp_path):
    rec = _confirmed()
    rec["whatever"] = 1
    errors = vf.validate_file(_write(tmp_path, "f.json", [rec]))
    assert any("extra keys" in e for e in errors)


def test_main_exit_codes(tmp_path, capsys):
    assert vf.main([_write(tmp_path, "f.json", [_confirmed()])]) == 0
    assert "PASS" in capsys.readouterr().out
    assert vf.main([_write(tmp_path, "g.json",
                           [{"verdict": "nope"}])]) == 1


# coverage ledger ----------------------------------------------------------

def _unit(**over):
    unit = {
        "coverage_id": "api%2Fsubmit.ts::internet::shop::injection",
        "canonical_refs": {"surface": "api/submit.ts", "boundary": "internet",
                           "subsystem": "shop", "attack_class": "injection"},
        "surface": "s", "boundary": "b", "subsystem": "s", "attack_class": "a",
        "starting_paths": ["api/"], "ordinary_attack_class_block": "x",
        "selected_companion_blocks": [], "excluded_blocks": [],
        "prior_status": "new", "attempts": [], "wave": 1,
        "status": "planned", "agent_id": "hunter-1",
        "reviewed_paths": [], "local_checks": [],
        "result_fingerprints": [], "unresolved": [],
    }
    unit.update(over)
    return unit


def test_valid_ledger_passes(tmp_path):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps([_unit()]), encoding="utf-8")
    assert vc.validate_file(str(p)) == []


def test_bad_coverage_id_encoding_fails(tmp_path):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps([_unit(coverage_id="wrong")]), encoding="utf-8")
    errors = vc.validate_file(str(p))
    assert any("canonical encoding" in e for e in errors)


def test_duplicate_ids_and_bad_agent(tmp_path):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps([_unit(), _unit(agent_id="CON")]),
                 encoding="utf-8")
    errors = vc.validate_file(str(p))
    assert any("duplicate coverage_id" in e for e in errors)
    assert any("agent_id" in e for e in errors)


def test_bad_status_rejected(tmp_path):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps([_unit(status="done")]), encoding="utf-8")
    assert vc.validate_file(str(p))


def test_ledger_main_exit_codes(tmp_path, capsys):
    p = tmp_path / "ledger.json"
    p.write_text(json.dumps([_unit()]), encoding="utf-8")
    assert vc.main([str(p)]) == 0
    assert "PASS" in capsys.readouterr().out
    p.write_text("[]", encoding="utf-8")
    assert vc.main([str(p)]) == 0  # empty ledger is valid
    p.write_text("{}", encoding="utf-8")
    assert vc.main([str(p)]) == 1


# skill-copy sync ----------------------------------------------------------
# The distributable plugin carries generated copies of the canonical
# `.claude/skills/*/SKILL.md` files (plus a provenance callout).
# `scripts/sync_skills.py` regenerates them; this test (and therefore CI,
# which runs the suite) fails on drift.

def _skill_paths(skill):
    root = Path(__file__).resolve().parent.parent
    return (root / ".claude" / "skills" / skill / "SKILL.md",
            root / "plugin" / "auditforge" / "skills" / skill / "SKILL.md")


@pytest.mark.parametrize("skill", ["auditforge", "security-audit"])
def test_skill_copies_in_sync(skill):
    canon, copy = _skill_paths(skill)
    assert canon.is_file(), canon
    assert copy.is_file(), copy
    expected = sync_skills.render(
        skill, canon.read_text(encoding="utf-8"))
    assert copy.read_text(encoding="utf-8") == expected, (
        "plugin copy drifted - regenerate with: "
        "python scripts/sync_skills.py")
