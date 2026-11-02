"""Tests for update_engines.py - best-effort engine refresh never fails."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import update_engines


def _result(returncode=0, out="ok"):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=out, stderr="")


def test_missing_tool_is_status_not_error():
    with patch("update_engines.shutil.which", return_value=None):
        assert update_engines._version("nope") == "missing"
        assert update_engines._refresh("nope", ["x"])["status"] == "missing"


def test_successful_refresh_reports_updated():
    with patch("update_engines.shutil.which", return_value="/bin/nuclei"), \
         patch("update_engines.subprocess.run",
               return_value=_result(0, "templates updated")):
        r = update_engines._refresh("nuclei", ["-update-templates"])
    assert r["status"] == "updated"


def test_failed_refresh_is_warning_not_raise():
    with patch("update_engines.shutil.which", return_value="/bin/trivy"), \
         patch("update_engines.subprocess.run", return_value=_result(1, "boom")):
        r = update_engines._refresh("trivy", ["db"])
    assert r["status"] == "failed"
    assert "exit 1" in r["detail"]


def test_timeout_is_warning_not_raise():
    with patch("update_engines.shutil.which", return_value="/bin/trivy"), \
         patch("update_engines.subprocess.run",
               side_effect=subprocess.TimeoutExpired("trivy", 600)):
        r = update_engines._refresh("trivy", ["db"])
    assert r["status"] == "failed"
    assert "timed out" in r["detail"]


def test_main_always_exits_zero(capsys):
    with patch("update_engines.shutil.which", return_value=None):
        assert update_engines.main([]) == 0
    out = capsys.readouterr().out
    assert "nuclei: missing" in out


def test_main_json_shape(capsys):
    with patch("update_engines.shutil.which", return_value=None):
        assert update_engines.main(["--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert set(data) == {"checkov", "semgrep", "trivy", "osv-scanner",
                         "nuclei", "scorecard", "trufflehog", "cargo-audit"}
    assert all("status" in v and "version" in v for v in data.values())
