"""Tests for sync_frameworks.py's _parse_attack() generalization (R-030):
wiring MITRE ATT&CK ICS and Mobile matrices in addition to Enterprise, each
as its own framework family since technique IDs aren't unique across
matrices. Uses small fake STIX bundles rather than the real ~40MB clones.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture(autouse=True)
def _restore_sources():
    # _fm_with rewrites FrameworkManager.SOURCES entries (a class attribute),
    # so snapshot and restore it around every test for isolation.
    from sync_frameworks import FrameworkManager
    saved = copy.deepcopy(FrameworkManager.SOURCES)
    yield
    FrameworkManager.SOURCES.clear()
    FrameworkManager.SOURCES.update(saved)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sync_frameworks import FrameworkManager  # noqa: E402


def _fake_stix_bundle(techniques: list) -> dict:
    objects = []
    for ext_id, name, revoked, deprecated in techniques:
        objects.append({
            "type": "attack-pattern",
            "name": name,
            "revoked": revoked,
            "x_mitre_deprecated": deprecated,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": ext_id},
            ],
        })
    return {"objects": objects}


def _write_matrix(tmp_path: Path, matrix_dir: str, techniques: list) -> Path:
    d = tmp_path / matrix_dir
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{matrix_dir}.json").write_text(
        json.dumps(_fake_stix_bundle(techniques)), encoding="utf-8"
    )
    return d


def test_parse_attack_enterprise_prefix_unchanged(tmp_path):
    d = _write_matrix(tmp_path, "enterprise-attack", [("T1552", "Unsecured Credentials", False, False)])
    fm = FrameworkManager()
    fm.SOURCES["attack"]["local_path"] = str(d)
    fm._parse_attack("attack", "ATTACK", "MITRE ATT&CK Enterprise")
    assert fm.metadata["controls"]["ATTACK:T1552"] == "Unsecured Credentials"
    assert fm.metadata["frameworks"]["ATTACK"] == "MITRE ATT&CK Enterprise"


def test_parse_attack_ics_gets_its_own_family(tmp_path):
    d = _write_matrix(tmp_path, "ics-attack", [("T0801", "Monitor Process State", False, False)])
    fm = FrameworkManager()
    fm.SOURCES["attack_ics"]["local_path"] = str(d)
    fm._parse_attack("attack_ics", "ATTACK_ICS", "MITRE ATT&CK ICS")
    assert fm.metadata["controls"]["ATTACK_ICS:T0801"] == "Monitor Process State"
    assert fm.metadata["frameworks"]["ATTACK_ICS"] == "MITRE ATT&CK ICS"
    # Enterprise's own family key must not have been touched
    assert "ATTACK" not in fm.metadata["frameworks"]


def test_parse_attack_mobile_gets_its_own_family(tmp_path):
    d = _write_matrix(tmp_path, "mobile-attack", [("T1398", "Boot or Logon Initialization Scripts", False, False)])
    fm = FrameworkManager()
    fm.SOURCES["attack_mobile"]["local_path"] = str(d)
    fm._parse_attack("attack_mobile", "ATTACK_MOBILE", "MITRE ATT&CK Mobile")
    assert fm.metadata["controls"]["ATTACK_MOBILE:T1398"] == "Boot or Logon Initialization Scripts"
    assert fm.metadata["frameworks"]["ATTACK_MOBILE"] == "MITRE ATT&CK Mobile"


def test_parse_attack_skips_revoked_and_deprecated(tmp_path):
    d = _write_matrix(tmp_path, "ics-attack", [
        ("T0801", "Live technique", False, False),
        ("T0802", "Revoked technique", True, False),
        ("T0803", "Deprecated technique", False, True),
    ])
    fm = FrameworkManager()
    fm.SOURCES["attack_ics"]["local_path"] = str(d)
    fm._parse_attack("attack_ics", "ATTACK_ICS", "MITRE ATT&CK ICS")
    assert "ATTACK_ICS:T0801" in fm.metadata["controls"]
    assert "ATTACK_ICS:T0802" not in fm.metadata["controls"]
    assert "ATTACK_ICS:T0803" not in fm.metadata["controls"]


def test_parse_attack_missing_matrix_dir_is_noop(tmp_path):
    fm = FrameworkManager()
    fm.SOURCES["attack_ics"]["local_path"] = str(tmp_path / "does-not-exist")
    fm._parse_attack("attack_ics", "ATTACK_ICS", "MITRE ATT&CK ICS")
    assert "ATTACK_ICS" not in fm.metadata["frameworks"]


def test_parse_attack_falls_back_to_versioned_filename(tmp_path):
    # Real clones sometimes only have e.g. ics-attack-19.2.json, not the
    # unversioned ics-attack.json alias - both must work.
    d = tmp_path / "ics-attack"
    d.mkdir()
    (d / "ics-attack-19.2.json").write_text(
        json.dumps(_fake_stix_bundle([("T0801", "Versioned file technique", False, False)])),
        encoding="utf-8",
    )
    fm = FrameworkManager()
    fm.SOURCES["attack_ics"]["local_path"] = str(d)
    fm._parse_attack("attack_ics", "ATTACK_ICS", "MITRE ATT&CK ICS")
    assert fm.metadata["controls"]["ATTACK_ICS:T0801"] == "Versioned file technique"


# Coverage-expansion tests below: SSDF, OWASP Top 10:2025, open drop-ins
# (SAMM / 800-63 / CVSS / BSIMM / CPG) and gated references/ drop-ins
# (CIS / CCM / HITRUST / CAIQ / AICM). All drop-in fixtures are synthetic
# (invented IDs and titles) - never real gated text.


def _fm_with(_ignored, tmp_path, key, subdir="dropin"):
    from sync_frameworks import FrameworkManager
    d = tmp_path / subdir
    d.mkdir(parents=True, exist_ok=True)
    fm = FrameworkManager()
    fm.SOURCES[key]["local_path"] = str(d)
    return fm, d


def test_parse_ssdf_reads_statement_prose(tmp_path):
    from sync_frameworks import FrameworkManager
    catalog = {
        "catalog": {"groups": [{
            "id": "PO", "title": "Prepare the Organization",
            "controls": [{
                "id": "PO.1", "title": "Define Security Requirements",
                "parts": [{"name": "statement",
                           "prose": "Define security requirements."}],
                "controls": [{
                    "id": "PO.1.1", "title": "PO.1.1",
                    "parts": [{"name": "statement",
                               "prose": "Identify and document all requirements."}],
                }],
            }],
        }]}
    }
    p = tmp_path / "ssdf.json"
    p.write_text(json.dumps(catalog), encoding="utf-8")
    fm = FrameworkManager()
    fm.SOURCES["ssdf"]["local_path"] = str(p)
    fm._parse_ssdf()
    assert fm.metadata["controls"]["SSDF:PO.1.1"] == \
        "Identify and document all requirements."
    assert fm.metadata["controls"]["SSDF:PO.1"] == "Define security requirements."
    assert fm.metadata["frameworks"]["SSDF"].startswith("NIST SP 800-218")


def test_parse_ssdf_real_catalog_has_tasks():
    # Guarded: runs against the vendored OSCAL file when present.
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    if not os.path.exists(fm.SOURCES["ssdf"]["local_path"]):
        pytest.skip("vendored SSDF catalog absent")
    fm._parse_ssdf()
    assert "SSDF" in fm.metadata["frameworks"]
    assert "SSDF:PO.1.1" in fm.metadata["controls"]
    assert "Identify and document" in fm.metadata["controls"]["SSDF:PO.1.1"]


def test_parse_ssdf_missing_file_is_noop(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    fm.SOURCES["ssdf"]["local_path"] = str(tmp_path / "does-not-exist.json")
    fm._parse_ssdf()
    assert "SSDF" not in fm.metadata["frameworks"]


def test_parse_top10_2025_from_markdown(tmp_path):
    from sync_frameworks import FrameworkManager
    d = tmp_path / "en"
    d.mkdir()
    (d / "A01_2025-Broken_Access_Control.md").write_text(
        "# A01:2025 Broken Access Control\n\n## Background.\n\n"
        "Maintaining its position at #1 in the Top Ten.\n", encoding="utf-8")
    (d / "A10_2025-Mishandling_of_Exceptional_Conditions.md").write_text(
        "# A10:2025 Mishandling of Exceptional Conditions\n\n## Background.\n\n"
        "A new category for 2025.\n", encoding="utf-8")
    (d / "index.md").write_text("# Index\n", encoding="utf-8")
    fm = FrameworkManager()
    fm.SOURCES["top10_2025"]["local_path"] = str(d)
    fm._parse_top10_2025()
    assert fm.metadata["controls"]["top10:A01"].startswith(
        "A01:2025 A01:2025 Broken Access Control")
    assert "position at #1" in fm.metadata["controls"]["top10:A01"]
    assert "new category" in fm.metadata["controls"]["top10:A10"]
    assert fm.metadata["frameworks"]["top10"] == "OWASP Top 10:2025"


def test_parse_top10_2025_real_docs_have_ten_categories():
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    if not os.path.isdir(fm.SOURCES["top10_2025"]["local_path"]):
        pytest.skip("owasp-top10 clone absent")
    fm._parse_top10_2025()
    for num in ("01", "03", "10"):
        assert f"top10:A{num}" in fm.metadata["controls"]
    assert len([k for k in fm.metadata["controls"] if k.startswith("top10:")]) == 10


def _owasp_spec(source_key):
    # Production wiring, not a copy: the same spec table sync_all consumes.
    from sync_frameworks import FrameworkManager
    return next(s for s in FrameworkManager.OWASP_CATEGORY_SPECS
                if s["source_key"] == source_key)


def test_parse_owasp_categories_api_title_and_section_lead(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "api_security")
    (d / "0xa1-broken-object-level-authorization.md").write_text(
        "# API1:2023 Broken Object Level Authorization\n\n"
        "| a | b |\n| - | - |\n| x | y |\n\n"
        "## Is the API Vulnerable?\n\nAccess control validates identity.\n",
        encoding="utf-8")
    (d / "0x00-header.md").write_text("# Header\n", encoding="utf-8")
    fm._parse_owasp_categories(**_owasp_spec("api_security"))
    entry = fm.metadata["controls"]["API:API1:2023"]
    assert entry.startswith("API1:2023 Broken Object Level Authorization")
    assert "Access control validates identity" in entry
    assert fm.metadata["frameworks"]["API"] == "OWASP API Security Top 10:2023"


def test_parse_owasp_categories_frontmatter_title_and_bold_label_skip(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "mobile")
    (d / "m1-improper-credential-usage.md").write_text(
        "---\nlayout: col-sidebar\ntitle: \"M1: Improper Credential Usage\"\n---\n\n"
        "# Threat Agents\n\n**Application Specific**\n\nHardcoded secrets leak.\n",
        encoding="utf-8")
    (d / "index.md").write_text("---\ntitle: \"Index\"\n---\n", encoding="utf-8")
    fm._parse_owasp_categories(**_owasp_spec("mobile"))
    entry = fm.metadata["controls"]["MOBILE:M1:2024"]
    assert entry.startswith("M1:2024 Improper Credential Usage")
    assert "Hardcoded secrets leak" in entry
    assert "**Application Specific**" not in entry


def test_parse_owasp_categories_skips_untitled_prefaces(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "llm")
    (d / "LLM00_Preface.md").write_text("# Preface\n\nSome intro.\n", encoding="utf-8")
    (d / "LLM01_PromptInjection.md").write_text(
        "## LLM01:2025 Prompt Injection\n\n### Description\n\nAltered behavior.\n",
        encoding="utf-8")
    fm._parse_owasp_categories(**_owasp_spec("llm"))
    assert not [k for k in fm.metadata["controls"] if "LLM00" in k]
    assert fm.metadata["controls"]["LLM:LLM01:2025"].startswith(
        "LLM01:2025 Prompt Injection")


def test_parse_owasp_categories_agentic_title_only(tmp_path):
    # Upstream Agentic draft bodies are still template placeholders, so the
    # production spec sets with_lead=False - only the title indexes.
    fm, d = _fm_with(pytest, tmp_path, "agentic")
    (d / "ASI01_Agent_Behaviour_Hijack .md").write_text(
        "## ASI01 \u2013 Agent Behaviour Hijack\n\n"
        "**Description:**\n\nFiller prose.\n", encoding="utf-8")
    fm._parse_owasp_categories(**_owasp_spec("agentic"))
    assert fm.metadata["controls"]["AGENTIC:ASI01:2026"] == \
        "ASI01:2026 Agent Behaviour Hijack"


def test_parse_owasp_categories_masvs_control_statement(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "masvs")
    (d / "MASVS-AUTH-1.md").write_text(
        "# MASVS-AUTH-1\n\n## Control\n\nThe app uses secure protocols.\n",
        encoding="utf-8")
    fm._parse_owasp_categories(**_owasp_spec("masvs"))
    assert fm.metadata["controls"]["MASVS:MASVS-AUTH-1"] == \
        "MASVS-AUTH-1 - The app uses secure protocols."


def test_parse_owasp_categories_missing_dir_is_noop(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    missing = str(tmp_path / "does-not-exist")
    for spec in FrameworkManager.OWASP_CATEGORY_SPECS:
        fm.SOURCES[spec["source_key"]]["local_path"] = missing
    for spec in FrameworkManager.OWASP_CATEGORY_SPECS:
        fm._parse_owasp_categories(**spec)
    assert fm.metadata["controls"] == {}
    assert fm.metadata["frameworks"] == {}


def test_parse_owasp_categories_real_clones_counts():
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    expected = {"api_security": 10, "mobile": 10, "llm": 10, "agentic": 10,
                "mcp": 10, "k8s": 10, "cicd": 10, "masvs": 24}
    for spec in FrameworkManager.OWASP_CATEGORY_SPECS:
        if not os.path.isdir(fm.SOURCES[spec["source_key"]]["local_path"]):
            pytest.skip(f"{spec['source_key']} clone absent")
        fm._parse_owasp_categories(**spec)
    for spec in FrameworkManager.OWASP_CATEGORY_SPECS:
        have = [k for k in fm.metadata["controls"]
                if k.startswith(spec["prefix"] + ":")]
        assert len(have) == expected[spec["source_key"]], spec["source_key"]
        assert fm.metadata["frameworks"][spec["prefix"]] == spec["label"]
    assert fm.metadata["controls"]["LLM:LLM01:2025"].startswith(
        "LLM01:2025 Prompt Injection")
    assert fm.metadata["controls"]["MCP:MCP01:2025"].startswith(
        "MCP01:2025 Token Mismanagement")
    assert fm.metadata["controls"]["CICD:CICD-SEC-1"].startswith(
        "CICD-SEC-1 Insufficient Flow Control")
    assert "securely stores sensitive data" in \
        fm.metadata["controls"]["MASVS:MASVS-STORAGE-1"]


def test_parse_samm_indexes_named_descriptions(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "samm")
    (d / "samm-model.yaml").write_text(yaml.safe_dump({
        "businessFunctions": [{
            "name": "Governance",
            "securityPractices": [{
                "name": "Strategy and Metrics",
                "activities": [
                    {"name": "Ensure executive support",
                     "description": "Obtain program-level sponsorship."},
                    {"name": "Junk without description"},
                ],
            }],
        }],
    }), encoding="utf-8")
    fm._parse_samm()
    assert fm.metadata["controls"]["SAMM:ENSURE_EXECUTIVE_SUPPORT"] == \
        "Obtain program-level sponsorship."
    assert "SAMM" in fm.metadata["frameworks"]


def test_parse_section_markdown_80063(tmp_path):
    import re
    from sync_frameworks import FrameworkManager
    fm, d = _fm_with(pytest, tmp_path, "nist80063")
    (d / "sp800-63-4.md").write_text(
        "# 4. Identity Assurance\n\n"
        "## 4.1 Identity Resolution\n\nResolution collects evidence.\n\n"
        "## Appendix: Glossary\n\nNo numbered sections here.\n", encoding="utf-8")
    fm._parse_section_markdown(
        "nist80063", "NIST80063", "NIST SP 800-63-4 Digital Identity Guidelines",
        re.compile(r"(?P<id>\d+(?:\.\d+)+)\s+(?P<title>.+)"))
    assert fm.metadata["controls"]["NIST80063:4.1"] == \
        "Identity Resolution - Resolution collects evidence."
    assert "NIST80063" in fm.metadata["frameworks"]


def test_parse_section_markdown_bsimm(tmp_path):
    import re
    from sync_frameworks import FrameworkManager
    fm, d = _fm_with(pytest, tmp_path, "bsimm")
    (d / "bsimm.md").write_text(
        "## Strategy & Metrics (SM)\n\nPlan the software security initiative.\n\n"
        "## Attack Models (AM)\n\nCreate data classification schemes.\n",
        encoding="utf-8")
    fm._parse_section_markdown(
        "bsimm", "BSIMM", "BSIMM Software Security Framework",
        re.compile(r"(?P<title>.+?)\s+\((?P<id>[A-Za-z]{1,4})\)\s*$"))
    assert fm.metadata["controls"]["BSIMM:SM"] == \
        "Strategy & Metrics - Plan the software security initiative."
    assert fm.metadata["controls"]["BSIMM:AM"].endswith(
        "Create data classification schemes.")


def test_parse_cvss_metrics_list(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "cvss")
    (d / "metrics.json").write_text(json.dumps({"metrics": [
        {"id": "AV", "name": "Attack Vector",
         "description": "Reflects the context by which exploitation is possible."},
        {"id": "XX", "name": "No description entry"},
    ]}), encoding="utf-8")
    fm._parse_cvss()
    assert fm.metadata["controls"]["CVSS:AV"] == \
        "Attack Vector: Reflects the context by which exploitation is possible."
    assert "CVSS:XX" not in fm.metadata["controls"]
    assert "CVSS" in fm.metadata["frameworks"]


def test_parse_reference_csv_cis_style(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "ref_cis")
    (d / "cis.csv").write_text(
        "Safeguard,Title,Description\n"
        "1.1,Establish and Maintain Detailed Enterprise Asset Inventory,\n"
        "2.3,Address Unauthorized Software,Remove or quarantine it.\n",
        encoding="utf-8")
    fm._parse_reference_csv("ref_cis", "CIS", "CIS Critical Security Controls v8.1")
    assert "Detailed Enterprise Asset Inventory" in fm.metadata["controls"]["CIS:1.1"]
    assert fm.metadata["controls"]["CIS:2.3"].endswith("Remove or quarantine it.")
    assert fm.metadata["frameworks"]["CIS"].endswith("(user-supplied drop-in)")


def test_parse_reference_csv_cpg_fallback_columns(tmp_path):
    # No recognized header names -> positional fallback (col 0 = id, col 1 = title).
    fm, d = _fm_with(pytest, tmp_path, "cisa_cpg")
    (d / "cpg.csv").write_text(
        "ref,statement\nCPG-1,Protect accounts with multifactor authentication.\n",
        encoding="utf-8")
    fm._parse_reference_csv("cisa_cpg", "CPG", "CISA Cybersecurity Performance Goals 2.0")
    assert fm.metadata["controls"]["CPG:CPG-1"] == \
        "Protect accounts with multifactor authentication."


def test_parse_reference_json_ccm_bundle(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "ref_ccm")
    (d / "ccm.json").write_text(json.dumps({
        "domains": {"Governance": [
            {"id": "GRM-01", "title": "Baseline Requirements",
             "description": "A governance program exists."},
        ]},
    }), encoding="utf-8")
    fm._parse_reference_json("ref_ccm", "CCM", "CSA Cloud Controls Matrix v4")
    assert fm.metadata["controls"]["CCM:GRM-01"] == \
        "Baseline Requirements - A governance program exists."
    assert "CCM" in fm.metadata["frameworks"]


def test_dropin_parsers_noop_when_dir_missing(tmp_path):
    import re
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    missing = str(tmp_path / "does-not-exist")
    for key in ("samm", "nist80063", "cvss", "bsimm", "cisa_cpg",
                "ref_cis", "ref_ccm", "ref_hitrust", "ref_caiq", "ref_aicm",
                "top10_2025", "api_security", "mobile", "llm", "agentic",
                "mcp", "k8s", "cicd", "masvs"):
        fm.SOURCES[key]["local_path"] = missing
    fm._parse_samm()
    fm._parse_section_markdown("nist80063", "NIST80063", "x",
                               re.compile(r"(?P<id>.+)\s+(?P<title>.+)"))
    fm._parse_section_markdown("bsimm", "BSIMM", "x",
                               re.compile(r"(?P<title>.+)\((?P<id>.+)\)"))
    fm._parse_cvss()
    fm._parse_top10_2025()
    for spec in FrameworkManager.OWASP_CATEGORY_SPECS:
        fm._parse_owasp_categories(**spec)
    for key, prefix, label in [
            ("cisa_cpg", "CPG", "x"), ("ref_cis", "CIS", "x"),
            ("ref_hitrust", "HITRUST", "x"), ("ref_caiq", "CAIQ", "x"),
            ("ref_aicm", "AICM", "x")]:
        fm._parse_reference_csv(key, prefix, label)
    fm._parse_reference_json("ref_ccm", "CCM", "x")
    assert fm.metadata["controls"] == {}
    assert fm.metadata["frameworks"] == {}


def test_gated_parsers_make_no_network_calls(tmp_path, monkeypatch):
    # The license gate is structural: drop-in parsers only touch local paths.
    import socket
    fm, d = _fm_with(pytest, tmp_path, "ref_hitrust")
    (d / "hitrust.csv").write_text(
        "id,title\n01.01,Access control policy is documented.\n", encoding="utf-8")
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("network call attempted")))
    fm._parse_reference_csv("ref_hitrust", "HITRUST", "HITRUST CSF")
    assert fm.metadata["controls"]["HITRUST:01.01"] == \
        "Access control policy is documented."


# MITRE SAF InSpec baseline tests: _parse_saf_inspec() indexes one entry
# per `control` block (ID/title/overview desc/tags). All fixtures below are
# synthetic (invented IDs and titles) - never real baseline text.


_SYNTH_AWS_RB = """\
control 'synth-demo-1.1' do
  title 'Maintain Primary Contact Details'
  desc "
    Ensure contact details are current and map to more than one individual.

    The provider uses these to contact the account owner. "

  desc 'rationale',
       "If the account misbehaves, the provider must reach someone. "
  desc 'check',
       'Review the contact details in the console.'

  impact 0.5
  tag nist: ['IR-6']
  tag severity: 'medium '
  tag cis_controls: [{ '8' => ['17.2'] }]

  describe 'placeholder' do
    it { should be_configured }
  end
end
"""

_SYNTH_MULTILINE_RB = """\
control "synth-demo-2.1" do
  title 'Ensure multi-factor authentication (MFA) is enabled for all users that have a console
password '
  desc 'MFA adds an extra layer of assurance beyond traditional credentials. '
  impact 0.7
  tag nist: ['IA-2', 'IA-2(1)']
  tag severity: 'high'
  tag cis_level: 1
  tag cis_rid: '2.1'

  describe 'placeholder' do
    skip 'manual check'
  end
end
control 'synth-demo-2.2' do
  title 'Title without overview prose'
  desc 'rationale',
       'Only a labeled desc exists - no overview to index. '
  impact 0.3
  tag severity: 'low'

  describe 'placeholder' do
    it { should be_configured }
  end
end
"""


def _write_rb(tmp_path, name, text):
    d = tmp_path / "controls"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(text, encoding="utf-8")
    return d


def test_parse_saf_inspec_indexes_title_desc_and_tags(tmp_path):
    from sync_frameworks import FrameworkManager
    d = _write_rb(tmp_path, "synth-demo-1.1.rb", _SYNTH_AWS_RB)
    fm = FrameworkManager()
    fm.SOURCES["saf_aws"]["local_path"] = str(d)
    fm._parse_saf_inspec("saf_aws", "SAF_AWS", "Synthetic SAF AWS")
    key = "SAF_AWS:SYNTH-DEMO-1.1"
    assert key in fm.metadata["controls"]
    entry = fm.metadata["controls"][key]
    assert entry.startswith("Maintain Primary Contact Details - Ensure contact details")
    # Labeled rationale/check bodies must not leak into the overview text.
    assert "must reach someone" not in entry
    assert "maps to NIST 800-53: IR-6" in entry
    assert "severity medium" in entry
    assert "impact 0.5" in entry
    assert fm.metadata["frameworks"]["SAF_AWS"] == "Synthetic SAF AWS"


def test_parse_saf_inspec_multiline_title_and_title_only(tmp_path):
    from sync_frameworks import FrameworkManager
    d = _write_rb(tmp_path, "synth-demo-2.rb", _SYNTH_MULTILINE_RB)
    fm = FrameworkManager()
    fm.SOURCES["saf_azure"]["local_path"] = str(d)
    fm._parse_saf_inspec("saf_azure", "SAF_AZURE", "Synthetic SAF Azure")
    multi = fm.metadata["controls"]["SAF_AZURE:SYNTH-DEMO-2.1"]
    assert multi.startswith(
        "Ensure multi-factor authentication (MFA) is enabled for all users "
        "that have a console password - MFA adds an extra layer")
    assert "maps to NIST 800-53: IA-2, IA-2(1)" in multi
    assert "CIS recommendation 2.1" in multi
    # Control with only a labeled desc degrades to a title-only entry.
    title_only = fm.metadata["controls"]["SAF_AZURE:SYNTH-DEMO-2.2"]
    assert title_only.startswith("Title without overview prose (")
    assert "Only a labeled desc" not in title_only


def test_parse_saf_inspec_missing_dir_is_noop(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    fm.SOURCES["saf_eks"]["local_path"] = str(tmp_path / "does-not-exist")
    fm._parse_saf_inspec("saf_eks", "SAF_EKS", "Synthetic SAF EKS")
    assert "SAF_EKS" not in fm.metadata["frameworks"]
    assert fm.metadata["controls"] == {}


def test_parse_saf_inspec_makes_no_network_calls(tmp_path, monkeypatch):
    # The license gate is structural: the SAF parser only touches local paths.
    import socket
    from sync_frameworks import FrameworkManager
    d = _write_rb(tmp_path, "synth-demo-1.1.rb", _SYNTH_AWS_RB)
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("network call attempted")))
    fm = FrameworkManager()
    fm.SOURCES["saf_aws"]["local_path"] = str(d)
    fm._parse_saf_inspec("saf_aws", "SAF_AWS", "Synthetic SAF AWS")
    assert "SAF_AWS:SYNTH-DEMO-1.1" in fm.metadata["controls"]


# Real-file-shaped fixtures below: synthetic content (invented IDs/titles)
# mirroring the exact key layouts observed in references/ (SAMM v2 datamodel
# `type` tags, 800-63-4 h-tag HTML, cvss_config.js metric objects, CCM
# domains[].controls[] with `specification`, InSpec #{var} interpolation).


def test_parse_samm_typed_datamodel_files(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "samm")
    (d / "Activity D-SA-1-A.yml").write_text(yaml.safe_dump({
        "type": "Activity", "title": "Adhere to basic security principles",
        "shortDescription": "Teams are trained during design.",
        "longDescription": "Longer prose here.",
    }), encoding="utf-8")
    (d / "Practice Level D-SA-1.yml").write_text(yaml.safe_dump({
        "type": "PracticeLevel", "practice": "some-guid",
        "maturitylevel": "other-guid",
        "objective": "Insert proactive guidance into design.",
    }), encoding="utf-8")
    (d / "Maturity Level 1.yml").write_text(yaml.safe_dump({
        "type": "MaturityLevel", "number": 1,
        "description": "Ad-hoc best effort implementation.",
    }), encoding="utf-8")
    (d / "Question D-SA-1-A.yml").write_text(yaml.safe_dump({
        "type": "Question", "text": "Do teams use principles?",
        "quality": ["Checklist exists"],
    }), encoding="utf-8")
    (d / "Answer Set A.yml").write_text(yaml.safe_dump({
        "type": "AnswerSet", "values": [{"text": "No", "value": 0}],
    }), encoding="utf-8")
    fm._parse_samm()
    assert fm.metadata["controls"]["SAMM:ACTIVITY_D_SA_1_A"] == \
        "Adhere to basic security principles - Teams are trained during design."
    assert fm.metadata["controls"]["SAMM:PRACTICELEVEL_LEVEL_D_SA_1"] == \
        "Practice level Level D-SA-1 - Insert proactive guidance into design."
    assert fm.metadata["controls"]["SAMM:MATURITYLEVEL_LEVEL_1"] == \
        "Maturity Level 1 - Ad-hoc best effort implementation."
    assert fm.metadata["controls"]["SAMM:QUESTION_D_SA_1_A"] == \
        "Do teams use principles? - Checklist exists"
    assert not [k for k in fm.metadata["controls"] if "ANSWERSET" in k]
    assert "SAMM" in fm.metadata["frameworks"]


def test_parse_nist80063_html_sections(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "nist80063")
    (d / "sp800-63b.html").write_text(
        '<h2 id="aal1req" data-section="2">\n'
        '  Authenticator Requirements '
        '<a href="#aal1req" class="header-link"><i>x</i></a>\n</h2>\n'
        '<p>Authenticators <strong>SHALL</strong> use approved crypto.</p>\n'
        '<h3 id="aal1reauth" data-section="2">Reauthentication</h3>\n'
        '<p>Two timeout types apply.</p>\n', encoding="utf-8")
    fm._parse_nist80063_html()
    assert fm.metadata["controls"]["NIST80063:63B-AAL1REQ"] == \
        "Authenticator Requirements - Authenticators SHALL use approved crypto."
    assert fm.metadata["controls"]["NIST80063:63B-AAL1REAUTH"] == \
        "Reauthentication - Two timeout types apply."
    assert "NIST80063" in fm.metadata["frameworks"]


def test_parse_nist80063_html_missing_dir_is_noop(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    fm.SOURCES["nist80063"]["local_path"] = str(tmp_path / "does-not-exist")
    fm._parse_nist80063_html()
    assert "NIST80063" not in fm.metadata["frameworks"]


def test_parse_cvss_from_raw_js(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "cvss")
    (d / "cvss_config.js").write_text(
        'cvssConfig = {\n  "Base Metrics": {\n'
        '    "Attack Vector (AV)": {\n'
        '      "tooltip": "Reflects the context of exploitation.",\n'
        '      "short": "AV",\n'
        '      "options": {\n'
        '        "Network (N)": {\n'
        '          "tooltip": "Remotely exploitable.",\n'
        '          "value": "N"\n'
        '        }\n'
        '      }\n'
        '    }\n'
        '  }\n}\n', encoding="utf-8")
    fm._parse_cvss()
    assert fm.metadata["controls"]["CVSS:AV"] == \
        "Attack Vector: Reflects the context of exploitation."
    # Option-level entries carry no `short` key and must not become metrics.
    assert "CVSS:N" not in fm.metadata["controls"]


def test_parse_reference_json_nested_specification(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "ref_ccm")
    (d / "ccm.json").write_text(json.dumps({
        "name": "Cloud Controls Matrix", "version": "4.1.0",
        "domains": [{"id": "A&A", "title": "Audit & Assurance", "controls": [
            {"id": "A&A-01", "title": "Policy and Procedures",
             "specification": "Establish and maintain policies."},
        ]}],
    }), encoding="utf-8")
    fm._parse_reference_json("ref_ccm", "CCM", "CSA Cloud Controls Matrix v4")
    assert fm.metadata["controls"]["CCM:A&A-01"] == \
        "Policy and Procedures - Establish and maintain policies."
    assert "CCM" in fm.metadata["frameworks"]


_SYNTH_GCP_RB = """\
title 'Ensure that corporate login credentials are used'

control_id = '1.1'
control_abbrev = 'iam'

control \"cis-gcp-#{control_id}-#{control_abbrev}\" do
  impact 'high'

  title \"[#{control_abbrev.upcase}] Ensure that corporate login credentials are used\"

  desc 'Use corporate login credentials instead of personal accounts.'
  desc 'rationale', 'Fully-managed accounts improve auditing.'

  tag cis_scored: true
  tag cis_level: 1
  tag cis_gcp: control_id.to_s

  describe 'placeholder' do
    it { should be_configured }
  end
end
"""


def test_parse_saf_inspec_resolves_interpolated_ids(tmp_path):
    from sync_frameworks import FrameworkManager
    d = _write_rb(tmp_path, "1.01-iam.rb", _SYNTH_GCP_RB)
    fm = FrameworkManager()
    fm.SOURCES["saf_gcp"]["local_path"] = str(d)
    fm._parse_saf_inspec("saf_gcp", "SAF_GCP", "Synthetic SAF GCP")
    key = "SAF_GCP:CIS-GCP-1.1-IAM"
    assert key in fm.metadata["controls"]
    entry = fm.metadata["controls"][key]
    assert entry.startswith(
        "[IAM] Ensure that corporate login credentials are used - "
        "Use corporate login credentials")
    assert "improve auditing" not in entry
    assert "CIS recommendation 1.1" in entry
    assert "impact high" in entry
    # No unresolved Ruby interpolation may leak into keys or entries.
    assert not [k for k in fm.metadata["controls"] if "#{" in k]
    assert "#{" not in entry


def test_parse_genai_from_text(tmp_path):
    from sync_frameworks import FrameworkManager
    text = ("MS-1.1-001 Employ methods to trace the origin of content.\n"
            "MS-1.1-002\n"
            "Integrate tools that analyze content provenance and detect\n"
            "anomalies across diverse populations.\n"
            "MG-2.2-001 Assess statistical biases in training data.\n")
    fm = FrameworkManager()
    fm.SOURCES["genai"]["local_path"] = str(tmp_path / "does-not-exist.pdf")
    fm._parse_genai_from_text(text)
    assert fm.metadata["controls"]["GENAI:MS-1.1-001"] == \
        "Employ methods to trace the origin of content."
    assert fm.metadata["controls"]["GENAI:MS-1.1-002"] == \
        ("Integrate tools that analyze content provenance and detect "
         "anomalies across diverse populations.")
    assert fm.metadata["controls"]["GENAI:MG-2.2-001"] == \
        "Assess statistical biases in training data."
    assert fm.metadata["frameworks"]["GENAI"].startswith("NIST AI 600-1")


def test_parse_genai_missing_pdf_is_noop(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    fm.SOURCES["genai"]["local_path"] = str(tmp_path / "does-not-exist.pdf")
    fm._parse_genai()
    assert "GENAI" not in fm.metadata["frameworks"]


def test_parse_genai_real_pdf_has_actions():
    # Guarded: runs against the fetched public-domain PDF when present.
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    if not os.path.exists(fm.SOURCES["genai"]["local_path"]):
        pytest.skip("GenAI profile PDF absent")
    fm._parse_genai()
    assert "GENAI" in fm.metadata["frameworks"]
    assert "GENAI:MS-1.1-001" in fm.metadata["controls"]
    assert "trace the origin" in fm.metadata["controls"]["GENAI:MS-1.1-001"]


# MITRE/AI expansion tests (R-067/R-068 + CWE/CAPEC/D3FEND): ATLAS v6 +
# legacy v5 YAML, D3FEND Turtle blocks, CWE/CAPEC XML, AI RMF subcategories.
# All fixtures are synthetic (invented IDs/titles) - never real source text.


def test_parse_atlas_v6_techniques_and_tactics(tmp_path):
    fm, _d = _fm_with(pytest, tmp_path, "atlas")
    v6 = tmp_path / "dropin" / "v6"
    v6.mkdir(parents=True, exist_ok=True)
    (v6 / "ATLAS-2026.09.yaml").write_text(yaml.safe_dump({
        "format-version": "6.0.0",
        "tactics": {"AML.TA0002": {"name": "Reconnaissance",
                                   "description": "Gather AI system info."}},
        "techniques": {
            "AML.T0000": {"name": "Search Open Technical Databases",
                          "description": "Adversaries search public research."},
            "AML.T0000.000": {"name": "Journals and Conference Proceedings",
                              "description": "Premier venue publications."},
        },
    }), encoding="utf-8")
    (v6 / "ATLAS-latest.yaml").write_text("ATLAS-2026.09.yaml",
                                          encoding="utf-8")
    fm.SOURCES["atlas"]["local_path"] = str(tmp_path / "dropin")
    fm._parse_atlas()
    assert fm.metadata["controls"]["ATLAS:AML.T0000"].startswith(
        "Search Open Technical Databases - Adversaries search")
    assert fm.metadata["controls"]["ATLAS:AML.T0000.000"].startswith(
        "Journals and Conference Proceedings")
    assert fm.metadata["controls"]["ATLAS:AML.TA0002"] == \
        "Reconnaissance - Gather AI system info."
    assert fm.metadata["frameworks"]["ATLAS"].startswith("MITRE ATLAS")


def test_parse_atlas_prefers_newest_dated_file(tmp_path):
    fm, _d = _fm_with(pytest, tmp_path, "atlas")
    v6 = tmp_path / "dropin" / "v6"
    v6.mkdir(parents=True, exist_ok=True)
    for ver, title in (("2026.03", "Old Title"), ("2026.09", "New Title")):
        (v6 / f"ATLAS-{ver}.yaml").write_text(yaml.safe_dump({
            "techniques": {"AML.T0000": {"name": title,
                                         "description": "Same desc."}},
        }), encoding="utf-8")
    fm.SOURCES["atlas"]["local_path"] = str(tmp_path / "dropin")
    fm._parse_atlas()
    assert fm.metadata["controls"]["ATLAS:AML.T0000"].startswith("New Title")


def test_parse_atlas_legacy_v5_matrices_shape(tmp_path):
    fm, _d = _fm_with(pytest, tmp_path, "atlas")
    (tmp_path / "dropin" / "ATLAS.yaml").write_text(yaml.safe_dump({
        "id": "ATLAS", "version": "5.6.0",
        "matrices": [{"id": "ATLAS", "name": "ATLAS Matrix",
                      "tactics": [{"id": "AML.TA0002", "name": "Recon",
                                   "description": "Gather info."}],
                      "techniques": [{"id": "AML.T0001",
                                      "name": "Craft Adversarial Data",
                                      "description": "Poison the well."}]}],
    }), encoding="utf-8")
    fm.SOURCES["atlas"]["local_path"] = str(tmp_path / "dropin")
    fm._parse_atlas()
    assert fm.metadata["controls"]["ATLAS:AML.T0001"].startswith(
        "Craft Adversarial Data")
    assert fm.metadata["controls"]["ATLAS:AML.TA0002"] == \
        "Recon - Gather info."


def test_parse_d3fend_labels_and_definitions(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "d3fend")
    (d / "d3fend-protege.ttl").write_text(
        "@prefix : <http://d3fend.mitre.org/ontologies/d3fend.owl#> .\n"
        "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n"
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
        ":NetworkTrafficAnalysis a :NetworkTrafficAnalysis,\n"
        "        owl:Class,\n"
        "        owl:NamedIndividual ;\n"
        '    rdfs:label "Network Traffic Analysis" ;\n'
        '    :d3fend-id "D3-NTA" ;\n'
        '    :definition "Interception and logging of network traffic." .\n'
        ":JunkNode a owl:Class ;\n"
        '    rdfs:label "No ID Here" .\n',
        encoding="utf-8")
    fm._parse_d3fend()
    assert fm.metadata["controls"]["D3FEND:D3-NTA"] == \
        "Network Traffic Analysis - Interception and logging of network traffic."
    assert not [k for k in fm.metadata["controls"] if "JUNK" in k.upper()]
    assert fm.metadata["frameworks"]["D3FEND"].startswith("MITRE D3FEND")


def test_parse_cwe_weaknesses_from_xml(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "cwe")
    (d / "cwec_v4.20.xml").write_text(
        '<?xml version="1.0"?>\n'
        '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">\n'
        '  <Weaknesses>\n'
        '    <Weakness ID="79" Name="Cross-site Scripting (XSS)">\n'
        '      <Description>The product does not neutralize code.</Description>\n'
        "    </Weakness>\n"
        '    <Weakness ID="89" Name="SQL Injection">\n'
        "      <Description>Special elements are not neutralized.</Description>\n"
        "    </Weakness>\n"
        '    <Weakness ID="000" Name="">\n'
        "      <Description>Nameless entries are skipped.</Description>\n"
        "    </Weakness>\n"
        "  </Weaknesses>\n"
        "</Weakness_Catalog>\n",
        encoding="utf-8")
    fm._parse_cwe()
    assert fm.metadata["controls"]["CWE:CWE-79"] == \
        "Cross-site Scripting (XSS) - The product does not neutralize code."
    assert fm.metadata["controls"]["CWE:CWE-89"].startswith("SQL Injection")
    assert "CWE:CWE-000" not in fm.metadata["controls"]
    assert fm.metadata["frameworks"]["CWE"].startswith("MITRE Common Weakness")


def test_parse_cwe_reads_inside_zip(tmp_path):
    import zipfile
    fm, d = _fm_with(pytest, tmp_path, "cwe")
    inner = ('<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">'
             '<Weakness ID="22" Name="Path Traversal">'
             "<Description>External input selects pathnames.</Description>"
             "</Weakness></Weakness_Catalog>")
    with zipfile.ZipFile(str(d / "cwec_latest.xml.zip"), "w") as zf:
        zf.writestr("cwec_v9.99.xml", inner)
    fm._parse_cwe()
    assert fm.metadata["controls"]["CWE:CWE-22"].startswith("Path Traversal")


def test_parse_capec_patterns_from_xml(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "capec")
    (d / "capec_latest.xml").write_text(
        '<?xml version="1.0"?>\n'
        '<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3">\n'
        '  <Attack_Pattern ID="1" Name="Accessing Functionality Not '
        'Properly Constrained by ACLs">\n'
        "    <Description>An adversary accesses functionality.</Description>\n"
        "  </Attack_Pattern>\n"
        "</Attack_Pattern_Catalog>\n",
        encoding="utf-8")
    fm._parse_capec()
    assert fm.metadata["controls"]["CAPEC:CAPEC-1"] == \
        ("Accessing Functionality Not Properly Constrained by ACLs - "
         "An adversary accesses functionality.")
    assert fm.metadata["frameworks"]["CAPEC"].startswith("MITRE Common Attack")


def test_parse_ai_rmf_from_text(tmp_path):
    fm = FrameworkManager()
    fm.SOURCES["ai_rmf"]["local_path"] = str(tmp_path / "does-not-exist")
    text = ("Table 1: Categories and subcategories for the GOVERN function.\n"
            "GOVERN 1:\nPolicies, processes,\n"
            "and practices are in place.\n"
            "GOVERN 1.1: Legal and regulatory requirements involving AI\n"
            "are understood, managed, and documented.\n"
            "GOVERN 1.2: The characteristics of trustworthy AI are inte-\n"
            "grated into organizational policies and practices.\n"
            "MAP 2.1: Knowledge about the AI system is documented.\n")
    fm._parse_ai_rmf_from_text(text)
    assert fm.metadata["controls"]["AIRMF:GOVERN-1.1"] == \
        "Legal and regulatory requirements involving AI are understood, managed, and documented."
    # Hyphenated PDF line-wraps rejoin without a space or hyphen.
    assert fm.metadata["controls"]["AIRMF:GOVERN-1.2"] == \
        ("The characteristics of trustworthy AI are integrated into "
         "organizational policies and practices.")
    assert fm.metadata["controls"]["AIRMF:MAP-2.1"].startswith(
        "Knowledge about the AI system")
    # Category headers ("GOVERN 1:", no minor) never become controls.
    assert not [k for k in fm.metadata["controls"] if k == "AIRMF:GOVERN-1"]
    assert fm.metadata["frameworks"]["AIRMF"].startswith("NIST AI Risk")


def test_new_mitre_ai_parsers_noop_when_absent(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    missing = str(tmp_path / "does-not-exist")
    for key in ("atlas", "d3fend", "cwe", "capec", "ai_rmf"):
        fm.SOURCES[key]["local_path"] = missing
    fm._parse_atlas()
    fm._parse_d3fend()
    fm._parse_cwe()
    fm._parse_capec()
    fm._parse_ai_rmf()
    assert fm.metadata["controls"] == {}
    assert fm.metadata["frameworks"] == {}


def test_new_mitre_ai_parsers_make_no_network_calls(tmp_path, monkeypatch):
    # Structural gate like the gated-parser test: local paths only.
    import socket
    fm, d = _fm_with(pytest, tmp_path, "cwe")
    (d / "cwec.xml").write_text(
        '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">'
        '<Weakness ID="1" Name="Sample"><Description>Text.</Description>'
        "</Weakness></Weakness_Catalog>", encoding="utf-8")
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("network call attempted")))
    fm._parse_cwe()
    assert fm.metadata["controls"]["CWE:CWE-1"] == "Sample - Text."


def test_new_mitre_ai_real_sources_when_present():
    # Guarded: runs against real clones/drop-ins when the refresh step has
    # populated them (mirrors the other *_real_* tests in this file).
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    if not os.path.isdir(fm.SOURCES["atlas"]["local_path"]):
        pytest.skip("atlas-data clone absent")
    fm._parse_atlas()
    assert "ATLAS" in fm.metadata["frameworks"]
    assert "ATLAS:AML.T0000" in fm.metadata["controls"]
    fm2 = FrameworkManager()
    if not os.path.exists(
            os.path.join(fm2.SOURCES["d3fend"]["local_path"],
                         "d3fend-protege.ttl")):
        pytest.skip("d3fend-ontology clone absent")
    fm2._parse_d3fend()
    assert "D3FEND:D3-NTA" in fm2.metadata["controls"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))


# Platform/regulation expansion (R-070 C2M2, R-103 SAF STIG baselines,
# R-104 DISA STIG XCCDF): fixtures are synthetic (invented IDs/titles),
# never real STIG/C2M2 text - except the guarded *_real_* tests, which run
# only when the refresh step has populated the local clone/drop-in.


def _write_xccdf(path, bench_title=None, groups=()):
    ns = 'xmlns="http://checklists.nist.gov/xccdf/1.2"'
    bench_attr = ""
    title_xml = ""
    if bench_title is not None:
        title_xml = f"<title>{bench_title}</title>"
    body = ""
    for gid, gtitle, rid, sev, desc in groups:
        body += (f'<Group id="{gid}"><title>{gtitle}</title>'
                 f'<description>Group text.</description>'
                 f'<Rule id="{rid}" severity="{sev}">'
                 f"<description>{desc}</description>"
                 "<check><check-content>Do the check.</check-content></check>"
                 "</Rule></Group>")
    path.write_text(f'<Benchmark {ns}{bench_attr}>{title_xml}{body}'
                    "</Benchmark>", encoding="utf-8")


def test_parse_stig_xccdf_groups_and_rules(tmp_path):
    fm, d = _fm_with(pytest, tmp_path, "stig_xccdf")
    _write_xccdf(d / "U_RHEL_8_V2R1_STIG_Manual-xccdf.xml",
                 bench_title="Red Hat Enterprise Linux 8 STIG",
                 groups=[("V-230221", "RHEL 8 must be a vendor-supported release.",
                          "SV-230221", "high", "A supported release gets patches."),
                         ("V-230222", "RHEL 8 must verify software downloads.",
                          "SV-230222", "medium", "Downloads get verified.")])
    assert fm._parse_stig_xccdf() is None
    controls = fm.metadata["controls"]
    assert controls["STIG:RED-HAT-ENTERPRISE-LINUX:V-230221"] == (
        "RHEL 8 must be a vendor-supported release. - "
        "A supported release gets patches. "
        "(STIG ID SV-230221; severity high)")
    assert "STIG:RED-HAT-ENTERPRISE-LINUX:V-230222" in controls
    assert fm.metadata["frameworks"]["STIG"] == (
        "DISA Security Technical Implementation Guides (XCCDF)")


def test_parse_stig_xccdf_strips_embedded_markup(tmp_path):
    # Real DISA descriptions carry entity-escaped <VulnDiscussion> etc.;
    # ElementTree decodes those to literal tag-like text that itertext()
    # passes through - the parser must strip them, keeping the prose.
    fm, d = _fm_with(pytest, tmp_path, "stig_xccdf")
    _write_xccdf(d / "U_DEMO_V1R1_STIG_Manual-xccdf.xml",
                 bench_title="Demo STIG",
                 groups=[("V-000001", "Demo requirement.",
                          "SV-000001", "high",
                          "&lt;VulnDiscussion&gt;Patches fix things."
                          "&lt;/VulnDiscussion&gt;")])
    assert fm._parse_stig_xccdf() is None
    entry = fm.metadata["controls"]["STIG:DEMO:V-000001"]
    assert "VulnDiscussion" not in entry
    assert "Patches fix things." in entry


def test_parse_stig_xccdf_namespaces_bench_per_file(tmp_path):
    # Same V-ID in two STIGs must not collide (benchmark namespace), and a
    # Benchmark @id is accepted when no <title> is present.
    fm, d = _fm_with(pytest, tmp_path, "stig_xccdf")
    ns1 = '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="WIN_2019_MS_STIG">'
    (d / "a.xml").write_text(
        f'{ns1}<Group id="V-230221"><title>Windows title.</title>'
        '<Rule id="SV-999" severity="low">'
        "<description>Windows desc.</description></Rule></Group></Benchmark>",
        encoding="utf-8")
    _write_xccdf(d / "b.xml", bench_title=None,
                 groups=[("V-230221", "Other title.", "SV-111", "high",
                          "Other desc.")])
    fm._parse_stig_xccdf()
    controls = fm.metadata["controls"]
    assert "STIG:WIN-2019-MS:V-230221" in controls
    assert "STIG:B:V-230221" in controls
    assert controls["STIG:WIN-2019-MS:V-230221"].startswith(
        "Windows title.")


def test_parse_stig_xccdf_reads_inside_zip(tmp_path, monkeypatch):
    import socket
    import zipfile
    fm, d = _fm_with(pytest, tmp_path, "stig_xccdf")
    (d / "note.txt").write_text("not xml", encoding="utf-8")
    with zipfile.ZipFile(d / "U_APP_V1R1_STIG.zip", "w") as zf:
        zf.writestr("U_APP_V1R1_STIG_Manual-xccdf.xml",
                    '<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2">'
                    "<title>App STIG</title>"
                    '<Group id="V-100"><title>App title.</title>'
                    '<Rule id="SV-100" severity="medium">'
                    "<description>App desc.</description></Rule></Group>"
                    "</Benchmark>")
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(
                            AssertionError("network call attempted")))
    fm._parse_stig_xccdf()
    assert fm.metadata["controls"]["STIG:APP:V-100"] == (
        "App title. - App desc. (STIG ID SV-100; severity medium)")


def test_stig_c2m2_parsers_noop_when_absent(tmp_path):
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    missing = str(tmp_path / "does-not-exist")
    for key in ("stig_xccdf", "c2m2", "saf_rhel8", "saf_rhel9"):
        fm.SOURCES[key]["local_path"] = missing
    fm._parse_stig_xccdf()
    fm._parse_c2m2()
    fm._parse_saf_inspec("saf_rhel8", "SAF_RHEL8", "x")
    fm._parse_saf_inspec("saf_rhel9", "SAF_RHEL9", "x")
    assert fm.metadata["controls"] == {}
    assert fm.metadata["frameworks"] == {}


def test_parse_ffiec_from_text_infosec(tmp_path):
    # R-057: FFIEC IT Handbook Information Security booklet shapes - dotted
    # subsections (II.C.19) and examination objectives; TOC lines with dot
    # leaders and lone page numbers must not index.
    fm, _d = _fm_with(pytest, tmp_path, "ffiec")
    text = (
        "II.C.19 Encryption ............................ 40 \n"
        "II.C.19 Encryption \n"
        "FFIEC IT Examination Handbook Information Security September 2016 \n"
        "iii \n"
        "Encryption protects the confidentiality of information. \n"
        "II.D Monitoring and Reporting \n"
        "Objective 1: Determine the appropriate scope and objectives. \n"
        "1. Review past reports for outstanding issues. \n"
        "Objective 2: Determine whether governance is effective. \n")
    n = fm._parse_ffiec_from_text(text)
    controls = fm.metadata["controls"]
    assert n == 4
    assert controls["FFIEC:IS-II-C-19"] == (
        "Encryption protects the confidentiality of information.")
    assert "FFIEC IT Examination Handbook" not in controls["FFIEC:IS-II-C-19"]
    assert controls["FFIEC:IS-OBJ1"] == (
        "Determine the appropriate scope and objectives. "
        "1. Review past reports for outstanding issues.")
    assert fm.metadata["frameworks"]["FFIEC"] == (
        "FFIEC IT Examination Handbook: Information Security")


def test_parse_ffiec_strips_inline_running_headers(tmp_path):
    # pypdf merges the running header, roman folio, and body start onto one
    # line ("September 2016 ii September 2016 1 Introduction ...") - the
    # header chunk and bare page folio must go, the prose must stay.
    fm, _d = _fm_with(pytest, tmp_path, "ffiec")
    text = (
        "II.A.3 Supervision of Resources \n"
        "September 2016 ii September 2016 1 Introduction \n"
        "This booklet September 2016 26 guides examiners. \n")
    n = fm._parse_ffiec_from_text(text)
    assert n == 1
    entry = fm.metadata["controls"]["FFIEC:IS-II-A-3"]
    assert entry == "Introduction This booklet guides examiners."


def test_parse_c2m2_from_text(tmp_path):
    fm, _d = _fm_with(pytest, tmp_path, "c2m2")
    text = (
        "Cybersecurity Capability Maturity Model, Version 2.1  CONTENTS \n"
        "6.1 Asset, Change, and Configuration Management (ASSET) ........ 36 \n"
        "1. Manage IT and OT Asset Inventory \n"
        "MIL1 a. Inventoried early, at least in an ad hoc manner \n"
        "6.1 Asset, Change, and Configuration Management \n"
        "(ASSET) \n"
        "The Asset, Change, and Configuration Management \n"
        "(ASSET) domain comprises five objectives: \n"
        "1. Manage IT and OT Asset Inventory \n"
        "2. Manage Information Asset Inventory \n"
        "Objectives and Practices \n"
        "1. Manage IT and OT Asset Inventory \n"
        "MIL1 a. IT and OT assets that are important to the delivery of the \n"
        "function are inventoried, at least in an ad hoc manner \n"
        "MIL2 b. The inventory includes assets that may be leveraged \n"
        "to achieve a threat objective \n"
        "c. Inventoried assets are prioritized based on defined criteria \n"
        "MIL3 f. The inventory is complete \n"
        "Figure 5: Example of Referencing an Individual Practice: ASSET-1a \n"
        "2. Manage Information Asset Inventory \n"
        "MIL1 a. Information assets are inventoried \n"
        "Cybersecurity Capability Maturity Model, Version 2.1  ASSET \n"
        "37 \n")
    n = fm._parse_c2m2_from_text(text)
    controls = fm.metadata["controls"]
    assert n == 5
    assert controls["C2M2:ASSET-1A"] == (
        "IT and OT assets that are important to the delivery of the function "
        "are inventoried, at least in an ad hoc manner "
        "(ASSET objective Manage IT and OT Asset Inventory, MIL1)")
    assert controls["C2M2:ASSET-1C"] == (
        "Inventoried assets are prioritized based on defined criteria "
        "(ASSET objective Manage IT and OT Asset Inventory, MIL2)")
    assert controls["C2M2:ASSET-1F"].endswith("MIL3)")
    assert controls["C2M2:ASSET-2A"].endswith(
        "(ASSET objective Manage Information Asset Inventory, MIL1)")
    assert fm.metadata["frameworks"]["C2M2"] == (
        "DOE Cybersecurity Capability Maturity Model v2.1")


def test_parse_c2m2_real_pdf_when_present():
    # Guarded: runs only when the refresh step has fetched the C2M2 PDF.
    from sync_frameworks import FrameworkManager
    fm = FrameworkManager()
    base = Path(fm.SOURCES["c2m2"]["local_path"])
    pdfs = sorted(base.glob("*.pdf")) if base.is_dir() else []
    if not pdfs:
        pytest.skip("references/c2m2 PDF absent")
    fm._parse_c2m2()
    assert "C2M2" in fm.metadata["frameworks"]
    assert "C2M2:ASSET-1A" in fm.metadata["controls"]
    assert "C2M2:THIRD-PARTIES-1A" in fm.metadata["controls"]
    assert sum(1 for k in fm.metadata["controls"]
               if k.startswith("C2M2:")) >= 300


def test_saf_stig_baselines_when_present():
    # Guarded: runs only when the SAF STIG clones exist (same pattern as
    # the other *_real_* tests); exercises the shared _parse_saf_inspec
    # against the SV-*.rb STIG shape (SV- file names, gtitle/gid tags).
    from sync_frameworks import FrameworkManager
    for key, prefix in (("saf_rhel8", "SAF_RHEL8"),
                        ("saf_rhel9", "SAF_RHEL9")):
        fm = FrameworkManager()
        if not os.path.isdir(fm.SOURCES[key]["local_path"]):
            pytest.skip(f"{key} clone absent")
        label = f"MITRE SAF {prefix} baseline"
        fm._parse_saf_inspec(key, prefix, label)
        assert fm.metadata["frameworks"][prefix] == label
        sv_keys = [k for k in fm.metadata["controls"]
                   if k.startswith(f"{prefix}:SV-")]
        assert len(sv_keys) >= 100, f"{prefix} indexed too few controls"
