"""Tests for policy_audit.py - governance/policy document coverage.

Uses synthetic target trees in tmp_path plus the real
framework_metadata.json for citation resolution (read-only, no network).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import policy_audit


@pytest.fixture()
def controls_index():
    return policy_audit.family_index(policy_audit.load_controls())


@pytest.fixture()
def policies():
    return policy_audit.load_policies()


def _doc(root: Path, rel: str, text: str):
    full = root / rel
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(text, encoding="utf-8")


def test_present_policy_with_file_and_content(tmp_path, policies,
                                              controls_index):
    _doc(tmp_path, "docs/access-control-policy.md",
         "# Access Control\nLeast privilege for all accounts. Quarterly "
         "access review. Automated provisioning and deprovisioning.\n")
    report = policy_audit.analyze(tmp_path, policies, controls_index, 2)
    got = {p["id"]: p for p in report["policies"]}
    assert got["access-control"]["status"] == "present"
    assert got["access-control"]["evidence_files"] == [
        "docs/access-control-policy.md"]


def test_missing_must_policy(tmp_path, policies, controls_index):
    report = policy_audit.analyze(tmp_path, policies, controls_index, 2)
    got = {p["id"]: p for p in report["policies"]}
    assert got["incident-response"]["status"] == "missing (must)"
    assert got["incident-response"]["must"] is True
    assert report["summary"]["missing (must)"] >= 1


def test_filename_only_is_partial(tmp_path, policies, controls_index):
    _doc(tmp_path, "incident-response-plan.md",
         "# TBD\nThis page intentionally left blank.\n")
    report = policy_audit.analyze(tmp_path, policies, controls_index, 2)
    got = {p["id"]: p for p in report["policies"]}
    assert got["incident-response"]["status"] == "partial"


def test_scattered_content_without_file_is_partial(tmp_path, policies,
                                                   controls_index):
    _doc(tmp_path, "README.md",
         "# Ops notes\nFirewall rules updated. Network segmentation applied. "
         "VPN required for ingress and egress traffic.\n")
    report = policy_audit.analyze(tmp_path, policies, controls_index, 2)
    got = {p["id"]: p for p in report["policies"]}
    # 4 distinct network-security keywords in README, no dedicated file
    assert got["network-security"]["status"] == "partial"


def test_citations_resolve_and_no_unresolved(tmp_path, policies,
                                             controls_index):
    _doc(tmp_path, "docs/risk-assessment.md",
         "# Risk Assessment\nAnnual risk assessment with risk register, "
         "risk treatment, likelihood and impact scoring.\n")
    report = policy_audit.analyze(tmp_path, policies, controls_index, 2)
    assert report["unresolved_refs"] == []
    got = {p["id"]: p for p in report["policies"]}
    assert got["risk-assessment"]["status"] == "present"
    assert len(got["risk-assessment"]["citations"]) >= 1
