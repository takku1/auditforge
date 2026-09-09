"""Tests for sync_frameworks.py's _parse_attack() generalization (R-030):
wiring MITRE ATT&CK ICS and Mobile matrices in addition to Enterprise, each
as its own framework family since technique IDs aren't unique across
matrices. Uses small fake STIX bundles rather than the real ~40MB clones.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

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


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
