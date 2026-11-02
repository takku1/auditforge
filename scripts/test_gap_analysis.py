"""Tests for gap_analysis.py - knowledge-driven must-build gap detection.

Uses synthetic target trees in tmp_path plus the real framework_metadata.json
for citation resolution (read-only, no network, no KB clones needed).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import gap_analysis


@pytest.fixture()
def controls_index():
    return gap_analysis.family_index(gap_analysis.load_controls())


@pytest.fixture()
def profiles():
    return {k: v for k, v in gap_analysis.load_profiles().items()
            if not k.startswith("_")}


def _site(root: Path, headers: bool = False):
    (root / "package.json").write_text('{"name": "shop"}\n', encoding="utf-8")
    (root / "index.html").write_text("<html></html>\n", encoding="utf-8")
    if headers:
        (root / "_headers").write_text("/*\n  X-Content-Type-Options: nosniff\n",
                                       encoding="utf-8")


def test_missing_headers_is_must_build_gap(tmp_path, profiles, controls_index):
    _site(tmp_path)
    report = gap_analysis.analyze(tmp_path, "website", set(),
                                  controls_index, profiles, 2)
    caps = {c["id"]: c for c in report["capabilities"]}
    assert caps["headers-config"]["status"] == "must-build gap"
    assert caps["headers-config"]["must"] is True
    assert report["summary"]["must-build gap"] >= 1
    assert report["unresolved_refs"] == []


def test_headers_present(tmp_path, profiles, controls_index):
    _site(tmp_path, headers=True)
    report = gap_analysis.analyze(tmp_path, "website", set(),
                                  controls_index, profiles, 2)
    caps = {c["id"]: c for c in report["capabilities"]}
    assert caps["headers-config"]["status"] == "present"
    assert caps["headers-config"]["evidence_files"] == ["_headers"]


def test_fired_rule_means_risk_observed(tmp_path, profiles, controls_index):
    _site(tmp_path)
    audit = tmp_path / "audit.json"
    audit.write_text(json.dumps({"findings": [{"rule_id": "WEB001"}]}),
                     encoding="utf-8")
    fired = gap_analysis.load_fired_rules(str(audit))
    assert fired == {"WEB001"}
    report = gap_analysis.analyze(tmp_path, "website", fired,
                                  controls_index, profiles, 2)
    caps = {c["id"]: c for c in report["capabilities"]}
    assert caps["headers-config"]["status"] == "risk-observed"
    assert caps["headers-config"]["fired_rules"] == ["WEB001"]


def test_citations_are_real_controls(tmp_path, profiles, controls_index):
    _site(tmp_path)
    report = gap_analysis.analyze(tmp_path, "website", set(),
                                  controls_index, profiles, 1)
    controls = gap_analysis.load_controls()
    cited = [cit["ref"] for c in report["capabilities"] for cit in c["citations"]]
    assert cited, "website profile should produce citations"
    for ref in cited:
        assert ref in controls, ref


def test_unknown_family_reported_not_dropped(controls_index):
    unresolved: list = []
    cites = gap_analysis.cite(controls_index, ["NO_SUCH_FAMILY_XYZ"],
                              ["tls"], 2, unresolved, "cap-x")
    assert cites == []
    assert unresolved == [{"capability": "cap-x", "family": "NO_SUCH_FAMILY_XYZ"}]


def test_walk_target_skips_unstatable_entries(tmp_path, monkeypatch):
    # Entries whose stat raises OSError (observed: a Linux venv's lib64
    # reparse point seen from Windows, WinError 1920 - even exists()
    # raises) must be skipped, not crash the whole analysis.
    (tmp_path / "index.html").write_text("<html></html>\n", encoding="utf-8")
    (tmp_path / "unstatable").write_text("x", encoding="utf-8")
    real_is_file = Path.is_file

    def flaky_is_file(self):
        if self.name == "unstatable":
            raise OSError("[WinError 1920] simulated unstatable entry")
        return real_is_file(self)

    monkeypatch.setattr(Path, "is_file", flaky_is_file)
    rels = gap_analysis.walk_target(tmp_path)
    assert "index.html" in rels
    assert "unstatable" not in rels


def test_autodetect_picks_known_domain(tmp_path, profiles):
    (tmp_path / "main.tf").write_text('resource "x" "y" {}\n', encoding="utf-8")
    (tmp_path / "variables.tf").write_text('variable "z" {}\n', encoding="utf-8")
    domain = gap_analysis.autodetect(gap_analysis.walk_target(tmp_path), profiles)
    assert domain in profiles


def test_every_profile_resolves_against_kb(profiles, controls_index):
    fams = set()
    for name, profile in profiles.items():
        for cap in profile["capabilities"]:
            fams.update(cap.get("families", []))
    index_fams = set(controls_index)
    missing = sorted(f for f in fams if f not in index_fams)
    assert missing == [], f"profile families absent from KB: {missing}"


def test_markdown_marks_must_build(tmp_path, profiles, controls_index):
    _site(tmp_path)
    report = gap_analysis.analyze(tmp_path, "website", set(),
                                  controls_index, profiles, 1)
    md = gap_analysis.to_markdown(report)
    assert "MUST-BUILD GAP" in md
    assert "# Gap analysis:" in md
