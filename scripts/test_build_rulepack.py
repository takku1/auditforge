#!/usr/bin/env python3
"""Tests for scripts/build_rulepack.py (ronin.rulepack/v1 builder)."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_rulepack as br  # noqa: E402

FIXED_CREATED_AT = "2026-08-25T00:00:00Z"
FIXED_VERSION = "2026.08.0"


@pytest.fixture(scope="module")
def pack() -> dict:
    return br.build_pack(FIXED_VERSION, "stable", FIXED_CREATED_AT)


# --- contract shape --------------------------------------------------------


def test_pack_header_matches_contract(pack):
    assert pack["schema"] == "ronin.rulepack/v1"
    assert pack["packId"] == "ronin-core"
    assert pack["version"] == FIXED_VERSION
    assert pack["channel"] == "stable"
    assert pack["minAgentVersion"] == "0.3.8"
    assert pack["createdAt"] == FIXED_CREATED_AT


def test_every_rule_carries_contract_fields(pack):
    required = {
        "id", "title", "domain", "platforms", "minTier", "severity",
        "tierSeverity", "controls", "remediation", "detector",
    }
    for rule in pack["rules"]:
        missing = required - set(rule)
        assert not missing, f"{rule.get('id')} missing {missing}"
        assert set(rule) == required, f"{rule['id']} has extra fields {set(rule)}"
        assert isinstance(rule["remediation"], str) and len(rule["remediation"]) > 20
        assert len(rule["controls"]) >= 1
        for control in rule["controls"]:
            assert control["framework"] in {"800-171", "800-172", "SOC2", "CIS"}
            assert control["ref"]


def test_builtin_validator_accepts_seed_catalog(pack):
    problems = br.validate_pack_shape(pack) + br.validate_rules(pack["rules"])
    br.validate_distribution(pack, problems)
    assert problems == []


def test_detector_types_allowed_and_coherent(pack):
    allowed = {"registry", "file-pattern", "service", "os-version"}
    for rule in pack["rules"]:
        det = rule["detector"]
        assert det["type"] in allowed, rule["id"]
        assert set(det["platforms"]) <= set(rule["platforms"]), rule["id"]
        if det["type"] == "registry":
            assert det["key"].startswith(("HKLM\\", "HKCU\\")), rule["id"]
            assert det["value"]
            assert len(det["violation"]) == 1
            op = next(iter(det["violation"]))
            assert op in br.VIOLATION_OPS, rule["id"]
        elif det["type"] == "file-pattern":
            assert det["paths"], rule["id"]
        elif det["type"] == "service":
            assert isinstance(det["expectRunning"], bool), rule["id"]
        elif det["type"] == "os-version":
            assert br.OS_VERSION_RE.match(det["minVersion"]), rule["id"]


def test_firewall_rules_use_registry_enablefirewall(pack):
    fw = [
        r for r in pack["rules"] if "FirewallPolicy" in r["detector"].get("key", "")
    ]
    assert fw, "expected host-firewall rules"
    for rule in fw:
        assert rule["detector"]["type"] == "registry"
        assert rule["detector"]["key"].startswith(
            r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess"
            r"\Parameters\FirewallPolicy"
        )
        assert rule["detector"]["value"] == "EnableFirewall"


# --- tier distribution & catalog hygiene ------------------------------------


def test_tier_minimums(pack):
    counts = {t: 0 for t in (1, 2, 3)}
    for rule in pack["rules"]:
        counts[rule["minTier"]] += 1
    assert counts[1] >= 5, "Essential tier under-populated"
    assert counts[2] >= 8, "Hardened tier under-populated"
    assert counts[3] >= 5, "Advanced tier under-populated"


def test_linux_cross_platform_rules(pack):
    linux = [r for r in pack["rules"] if r["platforms"] == ["LINUX"]]
    assert len(linux) >= 2
    sshd = [r for r in linux if "/etc/ssh/sshd_config" in r["detector"]["paths"][0]]
    assert sshd, "expected sshd_config rule"
    assert "PermitRootLogin" in sshd[0]["detector"]["contentRegex"]
    assert "PasswordAuthentication" in sshd[0]["detector"]["contentRegex"]
    assert any(
        "world-writable" in r["title"].lower() or r["id"] == "HOST-WWPATH-001"
        for r in linux
    ), "expected world-writable path rule"


def test_rule_ids_stable_format_unique(pack):
    ids = [r["id"] for r in pack["rules"]]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    for rid in ids:
        assert br.RULE_ID_RE.match(rid), f"bad id format {rid}"


def test_severity_vocab_and_escalations(pack):
    for rule in pack["rules"]:
        assert rule["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert isinstance(rule["tierSeverity"], dict)
        for tier_key, sev in rule["tierSeverity"].items():
            assert tier_key in {"1", "2", "3"}
            assert sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            assert order.index(sev) >= order.index(rule["severity"]), (
                f"{rule['id']} escalation de-escalates"
            )


def test_platforms_vocabulary(pack):
    for rule in pack["rules"]:
        assert rule["platforms"], rule["id"]
        assert set(rule["platforms"]) <= {"WINDOWS", "LINUX", "MACOS"}, rule["id"]


def test_required_tier1_subjects_present(pack):
    t1_keys = {
        "LanmanServer\\Parameters",
        "SCHANNEL",
        "Real-Time Protection",
        "FirewallPolicy\\PublicProfile",
        "Terminal Server",
    }
    keys = "\n".join(
        r["detector"].get("key", "")
        for r in pack["rules"]
        if r["minTier"] == 1 and r["detector"]["type"] == "registry"
    )
    for fragment in t1_keys:
        assert fragment in keys, f"missing T1 registry coverage for {fragment}"


# --- byte reproducibility ---------------------------------------------------


def test_reproducible_bytes_same_created_at():
    a = br.render_bytes(br.build_pack(FIXED_VERSION, "stable", FIXED_CREATED_AT))
    b = br.render_bytes(br.build_pack(FIXED_VERSION, "stable", FIXED_CREATED_AT))
    assert a == b


def test_created_at_changes_bytes():
    a = br.render_bytes(br.build_pack(FIXED_VERSION, "stable", FIXED_CREATED_AT))
    b = br.render_bytes(
        br.build_pack(FIXED_VERSION, "stable", "2026-08-26T12:00:00Z")
    )
    assert a != b


def test_utf8_no_bom_trailing_newline():
    data = br.render_bytes(br.build_pack(FIXED_VERSION, "stable", FIXED_CREATED_AT))
    assert not data.startswith(b"\xef\xbb\xbf")
    assert data.endswith(b"\n")


# --- end-to-end output tree --------------------------------------------------


def test_end_to_end_outputs(tmp_path):
    rc = br.main([
        "--out", str(tmp_path),
        "--version", FIXED_VERSION,
        "--channel", "stable",
        "--created-at", FIXED_CREATED_AT,
    ])
    assert rc == 0

    version_dir = tmp_path / FIXED_VERSION
    pack_path = version_dir / "pack.json"
    manifest_path = version_dir / "manifest.json"
    pointer_path = tmp_path / "channels" / "stable.json"
    assert pack_path.is_file() and manifest_path.is_file() and pointer_path.is_file()

    raw = pack_path.read_bytes()
    assert raw.endswith(b"\n") and not raw.startswith(b"\xef\xbb\xbf")

    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    assert pointer["packId"] == "ronin-core"
    assert pointer["channel"] == "stable"
    assert pointer["version"] == FIXED_VERSION
    assert pointer["sha256"] == hashlib.sha256(raw).hexdigest()
    assert pointer["sizeBytes"] == len(raw)
    assert pointer["updatedAt"] == FIXED_CREATED_AT

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    on_disk = json.loads(raw.decode("utf-8"))
    assert manifest["ruleCount"] == len(on_disk["rules"])
    expected = {"1": 0, "2": 0, "3": 0}
    for rule in on_disk["rules"]:
        expected[str(rule["minTier"])] += 1
    assert manifest["minTierCounts"] == expected


def test_rerun_is_byte_idempotent(tmp_path):
    argv = [
        "--out", str(tmp_path),
        "--created-at", FIXED_CREATED_AT,
    ]
    assert br.main(argv) == 0
    first_pack = (tmp_path / FIXED_VERSION / "pack.json").read_bytes()
    first_pointer = (tmp_path / "channels" / "stable.json").read_bytes()
    assert br.main(argv) == 0
    assert (tmp_path / FIXED_VERSION / "pack.json").read_bytes() == first_pack
    assert (tmp_path / "channels" / "stable.json").read_bytes() == first_pointer


def test_validation_fails_loudly_on_corrupt_catalog(monkeypatch, tmp_path, capsys):
    rules = br._rules()
    broken = dict(rules[0])
    broken["id"] = rules[-1]["id"]          # duplicate id
    broken["minTier"] = 9                    # invalid tier
    broken["severity"] = "APOCALYPTIC"       # invalid severity
    broken["platforms"] = ["BEOS"]           # invalid platform
    monkeypatch.setattr(br, "_rules", lambda: rules + [broken])
    rc = br.main(["--out", str(tmp_path), "--created-at", FIXED_CREATED_AT])
    captured = capsys.readouterr()
    assert rc == 2
    assert "validation failed" in captured.err
    for needle in ("duplicate rule id", "minTier", "severity", "platforms"):
        assert needle in captured.err
