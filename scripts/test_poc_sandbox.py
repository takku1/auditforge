"""Tests for poc_sandbox.py - hardened PoC execution boundary (R-138).

The docker backend is a stub python script (AUDITFORGE_DOCKER="<python>
<stub>") so no test needs a real Docker daemon; refusal paths are covered
by pointing the backend at a missing binary or a failing `info`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import audit_repo
import ledger
import poc_sandbox


STUB = """
import os, sys, time
log = os.environ.get("POC_STUB_LOG", "")
args = sys.argv[1:]
if log:
    open(log, "a").write(" ".join(args) + "\\n")
if args[:1] == ["info"]:
    sys.exit(int(os.environ.get("POC_STUB_INFO_RC", "0")))
if args[:2] == ["image", "inspect"] or (len(args) > 2 and args[0] == "image" and args[1] == "inspect"):
    sys.exit(0 if os.environ.get("POC_STUB_IMAGE_OK", "1") == "1" else 1)
if args[:1] == ["run"]:
    time.sleep(float(os.environ.get("POC_STUB_SLEEP", "0")))
    out = os.environ.get("POC_STUB_OUT", "")
    if out:
        Path = __import__("pathlib").Path
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / "repro.log").write_text("pwned\\n")
    print("stub-container-output")
    sys.exit(0)
if args[:2] == ["rm", "-f"]:
    sys.exit(0)
sys.exit(99)
"""


@pytest.fixture()
def stub(monkeypatch, tmp_path):
    stub_py = tmp_path / "docker_stub.py"
    stub_py.write_text(STUB, encoding="utf-8")
    log = tmp_path / "docker.log"
    monkeypatch.setenv("POC_STUB_LOG", str(log))
    monkeypatch.setenv("AUDITFORGE_DOCKER",
                       "%s %s" % (sys.executable, stub_py))
    for var in ("POC_STUB_INFO_RC", "POC_STUB_IMAGE_OK", "POC_STUB_SLEEP",
                "POC_STUB_OUT"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path


def test_refusal_without_backend(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("AUDITFORGE_DOCKER", "definitely-not-docker-xyz")
    rc = poc_sandbox.main(["run", "--cmd", "id",
                           "--workdir", str(tmp_path)])
    assert rc == 4
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "refused"
    assert payload["verdict"] == "needs_validation"
    assert payload["blocker"]


def test_refusal_when_daemon_down(stub, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("POC_STUB_INFO_RC", "1")
    rc = poc_sandbox.main(["run", "--cmd", "id",
                           "--workdir", str(tmp_path)])
    assert rc == 4
    assert json.loads(capsys.readouterr().out)["status"] == "refused"


def test_hardened_flags(stub, tmp_path):
    outdir = tmp_path / "out"
    res = poc_sandbox.run_poc(["id"], str(tmp_path), "img:test", 30,
                              str(outdir))
    assert res["status"] == "completed"
    logged = (stub / "docker.log").read_text(encoding="utf-8")
    run_line = [l for l in logged.splitlines()
                if l.startswith("run ")][0]
    for flag in ("--network none", "--cap-drop ALL",
                 "--security-opt no-new-privileges:true", "--read-only",
                 "--pids-limit 64", "--memory 256m", "--pull never",
                 "--rm", "--tmpfs", "-w /work", "/work:ro", "/out:rw"):
        assert flag in run_line, flag
    assert "docker.sock" not in logged
    assert ".aws" not in logged


def test_timeout_kills_container(stub, monkeypatch, tmp_path):
    monkeypatch.setenv("POC_STUB_SLEEP", "30")
    outdir = tmp_path / "out"
    res = poc_sandbox.run_poc(["sleep", "30"], str(tmp_path), "img:test",
                              1, str(outdir))
    assert res["status"] == "timeout"
    logged = (stub / "docker.log").read_text(encoding="utf-8")
    assert "rm -f auditforge-poc-" in logged


def test_refusal_records_needs_validation(stub, monkeypatch, tmp_path,
                                          capsys):
    db = str(tmp_path / "ledger.db")
    report = {"findings": [{"fingerprint": "fp1", "rule_id": "SEC001",
                             "severity": "CRITICAL", "file": "a.py",
                             "line": 1, "snippet": "s", "frameworks": []}]}
    p = tmp_path / "r.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    assert ledger.main(["--db", db, "ingest", "--repo", "shop",
                        "--run-id", "r1", "--audit-json", str(p)]) == 0
    capsys.readouterr()
    monkeypatch.setenv("AUDITFORGE_DOCKER", "definitely-not-docker-xyz")
    rc = poc_sandbox.main(["run", "--cmd", "id",
                           "--workdir", str(tmp_path),
                           "--record", "--repo", "shop",
                           "--fingerprint", "fp1", "--run-id", "poc1",
                           "--db", db, "--verifier", "hunter-1"])
    assert rc == 4
    capsys.readouterr()
    assert ledger.main(["--db", db, "list", "--repo", "shop",
                        "--verdict", "needs_validation",
                        "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 1 and rows[0]["fingerprint"] == "fp1"


def test_e2e_fixture_to_confirmed(stub, monkeypatch, tmp_path, capsys):
    # One end-to-end on an intentionally vulnerable local fixture: scan,
    # ingest, verify, sandboxed PoC, confirm - with finder != checker
    # enforced at every step. The SEC001 trigger is split across literals
    # so this file itself never matches the rule it tests.
    app = tmp_path / "app"
    app.mkdir()
    (app / "vuln.py").write_text(
        "pass" "word = \"s3cr3t-hunter-value\"\n", encoding="utf-8")
    assert audit_repo.main([str(app), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(f["rule_id"] == "SEC001" for f in report["findings"])
    rep_path = tmp_path / "report.json"
    rep_path.write_text(json.dumps(report), encoding="utf-8")
    db = str(tmp_path / "ledger.db")
    assert ledger.main(["--db", db, "ingest", "--repo", "shop",
                        "--run-id", "r1", "--audit-json", str(rep_path),
                        "--finder", "hunter-e2e"]) == 0
    capsys.readouterr()
    assert ledger.main(["--db", db, "list", "--repo", "shop",
                        "--format", "json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert len(listed) == 1 and listed[0]["finder"] == "hunter-e2e"
    fp = listed[0]["fingerprint"]
    assert ledger.main(["--db", db, "verdict", "--repo", "shop",
                        "--fingerprint", fp,
                        "--verdict", "needs_validation",
                        "--run-id", "v1", "--reason", "needs PoC",
                        "--verifier", "reviewer-e2e"]) == 0
    capsys.readouterr()
    outdir = tmp_path / "out"
    monkeypatch.setenv("POC_STUB_OUT", str(outdir))
    rc = poc_sandbox.main(["run", "--cmd", "python /work/app/vuln.py",
                           "--workdir", str(tmp_path), "--image", "img:test",
                           "--timeout", "30", "--outdir", str(outdir)])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "completed"
    assert payload["artifacts"] == ["repro.log"]
    evidence = str(outdir / "repro.log")
    assert ledger.main(["--db", db, "verdict", "--repo", "shop",
                        "--fingerprint", fp, "--verdict", "confirmed",
                        "--run-id", "v2", "--reason", "PoC reproduced",
                        "--verifier", "reviewer-e2e",
                        "--evidence", evidence]) == 0
    capsys.readouterr()
    assert ledger.main(["--db", db, "transitions", "--repo", "shop",
                        "--fingerprint", fp, "--format", "json"]) == 0
    chain = [(t["from_verdict"], t["to_verdict"])
             for t in json.loads(capsys.readouterr().out)]
    assert chain == [("unreviewed", "needs_validation"),
                     ("needs_validation", "confirmed")]
