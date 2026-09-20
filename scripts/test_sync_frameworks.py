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
                "top10_2025"):
        fm.SOURCES[key]["local_path"] = missing
    fm._parse_samm()
    fm._parse_section_markdown("nist80063", "NIST80063", "x",
                               re.compile(r"(?P<id>.+)\s+(?P<title>.+)"))
    fm._parse_section_markdown("bsimm", "BSIMM", "x",
                               re.compile(r"(?P<title>.+)\((?P<id>.+)\)"))
    fm._parse_cvss()
    fm._parse_top10_2025()
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


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
