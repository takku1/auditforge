"""Tests for benchmark.py - R-141 frozen evaluation infrastructure.

Fail-closed behavior is the point: missing ground truth, revision drift,
or incomplete execution metadata must refuse, never score anyway.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark as bm


def _manifest(tmp_path, target_dir, revision=None):
    m = {"version": 1,
         "targets": {"mini": {"kind": "local-fixture",
                              "path": str(target_dir),
                              "revision": revision}},
         "ground_truth": {"mini": "gt.json"},
         "configs": ["scanner-only", "scanner-hunter", "full-lifecycle"],
         "budgets": {"scanner-only": {"max_seconds": 600}}}
    p = tmp_path / "manifest.json"
    p.write_text(json.dumps(m), encoding="utf-8")
    return str(p)


def _fixture_app(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    # SEC001 trigger split across literals so this file never matches it.
    (app / "vuln.py").write_text(
        "pass" "word = 's3cr3t-hunter-value'" + chr(10),
        encoding="utf-8")
    (app / "safe.py").write_text(
        chr(10).join(["import os",
                       "password = os.environ.get(",
                       '    ' + chr(39) + 'APP_PASSWORD' + chr(39)
                       + chr(44) + chr(32) + chr(39) + chr(39) + chr(41)]),
        encoding="utf-8")
    return app


def _gt(path="vuln.py", line=1, rule="SEC001", rev="test-rev"):
    return {"target": "mini", "revision": rev,
            "vulns": [{"id": "V1", "file": path, "line": line,
                       "cwe": "CWE-798", "rule": rule,
                       "notes": "hardcoded credential"}],
            "safe": [{"id": "S1", "file": "safe.py", "line": 1,
                      "notes": "env-sourced secret"}]}


def test_run_scanner_records_pinned_run(tmp_path, capsys):
    app = _fixture_app(tmp_path)
    man = _manifest(tmp_path, app)
    out = tmp_path / "run"
    assert bm.main(["run-scanner", "--manifest", man, "--target", "mini",
                    "--out", str(out)]) == 0
    meta = json.loads((out / "meta.json").read_text(encoding="utf-8"))
    assert meta["config"] == "scanner-only"
    assert meta["revision"].startswith("content:")
    findings = json.loads((out / "findings.json").read_text(
        encoding="utf-8"))["findings"]
    assert any(f["rule_id"] == "SEC001" for f in findings)


def test_run_scanner_enforces_pinned_revision(tmp_path, capsys):
    app = _fixture_app(tmp_path)
    man = _manifest(tmp_path, app, revision="git:deadbeef")
    assert bm.main(["run-scanner", "--manifest", man, "--target", "mini",
                    "--out", str(tmp_path / "o")]) == 2


def test_run_scanner_refuses_unknown_target(tmp_path, capsys):
    man = _manifest(tmp_path, tmp_path / "app")
    assert bm.main(["run-scanner", "--manifest", man, "--target", "nope",
                    "--out", str(tmp_path / "o")]) == 2


def test_record_rejects_incomplete_metadata(tmp_path):
    man = _manifest(tmp_path, tmp_path)
    f = tmp_path / "findings.json"
    f.write_text(json.dumps({"findings": []}), encoding="utf-8")
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"config": "full-lifecycle"}),
                    encoding="utf-8")
    out = tmp_path / "run"
    rc = bm.main(["record", "--manifest", man, "--target", "mini",
                  "--config", "full-lifecycle", "--findings", str(f),
                  "--meta", str(meta), "--out", str(out)])
    assert rc == 2


def test_record_accepts_scanner_only(tmp_path):
    man = _manifest(tmp_path, tmp_path)
    f = tmp_path / "findings.json"
    f.write_text(json.dumps({"findings": []}), encoding="utf-8")
    meta = tmp_path / "meta.json"
    meta.write_text(json.dumps({"config": "scanner-only",
                                "target": "mini", "revision": "test-rev",
                                "tool": "audit_repo", "duration_s": 3}),
                    encoding="utf-8")
    out = tmp_path / "run"
    assert bm.main(["record", "--manifest", man, "--target", "mini",
                    "--config", "scanner-only", "--findings", str(f),
                    "--meta", str(meta), "--out", str(out)]) == 0
    assert (out / "run.json").exists()


def _run_dir(tmp_path, findings, meta_extra=None):
    d = tmp_path / "rundir"
    d.mkdir()
    (d / "findings.json").write_text(json.dumps({"findings": findings}),
                                     encoding="utf-8")
    meta = {"config": "scanner-only", "target": "mini",
            "revision": "test-rev", "tool": "audit_repo", "duration_s": 1}
    meta.update(meta_extra or {})
    (d / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


def _finding(rule="SEC001", file="vuln.py", line=1, fw="default"):
    if fw == "default":
        fw = ["CWE-798"]
    return {"rule_id": rule, "file": file, "line": line,
            "soc2_controls": fw}


def test_score_counts_tp_fn_fp(tmp_path, capsys):
    run = _run_dir(tmp_path, [_finding()])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert (m["tp"], m["fn"], m["fp"]) == (1, 0, 0)
    assert m["recall"] == 1.0 and m["precision"] == 1.0


def test_score_miss_and_noise(tmp_path, capsys):
    run = _run_dir(tmp_path, [_finding(rule="WEB003", file="other.py",
                                       line=9, fw=[])])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert (m["tp"], m["fn"], m["fp"]) == (0, 1, 1)
    assert m["precision"] == 0.0 and m["recall"] == 0.0


def test_score_safe_violation_is_fp(tmp_path, capsys):
    run = _run_dir(tmp_path, [_finding(rule="SEC001", file="safe.py",
                                       line=2, fw=["CWE-798"])])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert m["fp"] == 1 and m["safe_violated"] == ["S1"]
    assert m["safe_clean"] == 0


def test_score_refuses_revision_mismatch(tmp_path, capsys):
    run = _run_dir(tmp_path, [], meta_extra={"revision": "other-rev"})
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 2


def test_score_assigns_adjacent_vulns(tmp_path, capsys):
    # V4 (line 3) and V5 (line 4) share match windows; nearest-wins must
    # credit both instead of starving the neighbor.
    run = _run_dir(tmp_path, [_finding(line=3), _finding(line=4)])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps({"target": "mini", "revision": "test-rev",
                              "vulns": [
                                  {"id": "V4", "file": "vuln.py", "line": 3,
                                   "cwe": "CWE-798", "rule": "SEC001",
                                   "notes": "first"},
                                  {"id": "V5", "file": "vuln.py", "line": 4,
                                   "cwe": "CWE-798", "rule": "SEC001",
                                   "notes": "neighbor"}],
                              "safe": []}),
                  encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert (m["tp"], m["fn"], m["fp"]) == (2, 0, 0)


def test_score_reports_misclassified_location(tmp_path, capsys):
    # Right file+line, wrong rule: located but not classified.
    run = _run_dir(tmp_path, [_finding(rule="WEB003", line=1, fw=[])])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert (m["tp"], m["fn"]) == (0, 1)
    assert m["located"] == 1 and m["misclassified"] == ["V1"]


def test_score_dedupes_same_rule_line(tmp_path, capsys):
    dup = [_finding(), _finding()]
    run = _run_dir(tmp_path, dup)
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert (m["tp"], m["fn"], m["fp"]) == (1, 0, 0)


def test_youden_uses_safe_sample(tmp_path, capsys):
    run = _run_dir(tmp_path, [_finding()])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    out = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(out)]) == 0
    m = json.loads((out / "metrics.json").read_text(encoding="utf-8"))
    assert m["youdens_j_safe_sample"] == pytest.approx(1.0)
    assert m["tn_basis"] == "safe-sample"


def test_scorecard_and_limitations_emit_markdown(tmp_path, capsys):
    run = _run_dir(tmp_path, [_finding()])
    gt = tmp_path / "gt.json"
    gt.write_text(json.dumps(_gt()), encoding="utf-8")
    scored = tmp_path / "scored"
    assert bm.main(["score", "--run", str(run), "--ground-truth", str(gt),
                    "--out", str(scored)]) == 0
    card = tmp_path / "scorecard.md"
    assert bm.main(["scorecard", "--results", str(scored),
                    "--out", str(card)]) == 0
    text = card.read_text(encoding="utf-8")
    assert "| scanner-only |" in text and "precision" in text
    lim = tmp_path / "limitations.md"
    assert bm.main(["limitations", "--results", str(scored),
                    "--out", str(lim)]) == 0
    assert "Limitations" in lim.read_text(encoding="utf-8")
