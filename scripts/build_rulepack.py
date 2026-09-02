#!/usr/bin/env python3
"""Build the Ronin core posture rule pack (schema ``ronin.rulepack/v1``).

AuditForge is the rule-authoring brain for the Ronin posture engine
(Z:/roninai). This script embeds a curated seed catalog of host rules and
emits, under ``<out>/``:

  <out>/<version>/pack.json      exact contract shape (ronin.rulepack/v1)
  <out>/<version>/manifest.json  human manifest (ruleCount + minTierCounts)
  <out>/channels/<channel>.json  pointer {packId,channel,version,sha256,
                                 sizeBytes,updatedAt} over the exact pack.json
                                 bytes (UTF-8 no BOM, trailing newline)

All writes are atomic (temp file + os.replace). Output bytes are idempotent:
given the same --created-at, reruns produce byte-identical files.

Detector types allowed in this pack: registry | file-pattern | service |
os-version. Host-firewall rules intentionally use *registry* detectors against
HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\
<Domain|Public|Standard>\\EnableFirewall rather than the firewall-profile type,
so the checked value is the literal on-host policy value.

``violation`` is a single-operator condition object marking a violation:
{"equals": v} | {"notEquals": v} | {"gt": n} | {"gte": n} | {"lt": n} |
{"lte": n}. For file-pattern detectors an optional boolean ``requireMatch``
(default false) flips semantics: false = any match is a violation (autoruns);
true = matched artifact is required and its ABSENCE is the violation
(AppLocker / audit-policy export markers).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime
from pathlib import Path

SCHEMA = "ronin.rulepack/v1"
PACK_ID = "ronin-core"
MIN_AGENT_VERSION = "0.3.8"
DEFAULT_VERSION = "2026.08.0"
DEFAULT_CHANNEL = "stable"
DEFAULT_CREATED_AT = "2026-08-25T00:00:00Z"

DOMAINS = {"transport", "auth", "logging", "patching", "hardening", "crypto"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
PLATFORMS = {"WINDOWS", "LINUX", "MACOS"}
DETECTOR_TYPES = {"registry", "file-pattern", "service", "os-version"}
VIOLATION_OPS = {"equals", "notEquals", "gt", "gte", "lt", "lte"}
TIER_MINIMUMS = {1: 5, 2: 8, 3: 5}
LINUX_MIN_RULES = 2

RULE_ID_RE = re.compile(r"^HOST-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}$")
VERSION_RE = re.compile(r"^\d{4}\.\d{1,2}\.\d+$")
OS_VERSION_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?$")

# --- curated seed catalog -------------------------------------------------
# Tier ladder anchors (CONTRACTS.md section 1):
#   T1 Essential - world-exposed admin surfaces, SMBv1, legacy TLS, AV off
#   T2 Hardened  - screen lock, audit logging, local-admin sprawl, autoruns
#   T3 Advanced  - AppLocker, Credential Guard, WinRM/LLMNR/NLA surface


def _reg(key: str, value: str, violation: dict) -> dict:
    return {
        "type": "registry",
        "platforms": ["WINDOWS"],
        "key": key,
        "value": value,
        "violation": violation,
    }


def _fp(paths: list, content_regex=None, max_depth=None, require_match=False) -> dict:
    det = {"type": "file-pattern", "platforms": ["WINDOWS"], "paths": paths}
    if content_regex is not None:
        det["contentRegex"] = content_regex
    if max_depth is not None:
        det["maxDepth"] = max_depth
    if require_match:
        det["requireMatch"] = True
    return det


def _rules() -> list:
    return [
        # ---------------- Tier 1 - Essential -------------------------------
        {
            "id": "HOST-SMB1-001",
            "title": "SMBv1 protocol enabled on LanmanServer",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 1,
            "severity": "HIGH",
            "tierSeverity": {"3": "CRITICAL"},
            "controls": [
                {"framework": "800-171", "ref": "3.4.8"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-4.8"},
            ],
            "remediation": (
                "Disable SMBv1 by setting HKLM\\SYSTEM\\CurrentControlSet\\Services"
                "\\LanmanServer\\Parameters\\SMB1 to 0, then reboot. Remove the "
                "FS-SMB1 Windows feature where present."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                "SMB1",
                {"equals": 1},
            ),
        },
        {
            "id": "HOST-TLS-LEGACY-001",
            "title": "Legacy TLS protocol versions enabled (SChannel)",
            "domain": "transport",
            "platforms": ["WINDOWS"],
            "minTier": 1,
            "severity": "HIGH",
            "tierSeverity": {"3": "CRITICAL"},
            "controls": [
                {"framework": "800-171", "ref": "3.13.8"},
                {"framework": "SOC2", "ref": "CC6.7"},
            ],
            "remediation": (
                "Disable TLS 1.0/1.1 via SChannel registry keys: set Enabled=0 and "
                "DisabledByDefault=1 under HKLM\\SYSTEM\\CurrentControlSet\\Control"
                "\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server (and the "
                "TLS 1.1 equivalent), then reboot."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
                r"\Protocols\TLS 1.0\Server",
                "Enabled",
                {"equals": 1},
            ),
        },
        {
            "id": "HOST-DEFENDER-RTP-001",
            "title": "Microsoft Defender real-time protection disabled",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 1,
            "severity": "CRITICAL",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.14.2"},
                {"framework": "SOC2", "ref": "CC6.8"},
                {"framework": "CIS", "ref": "v8-10.1"},
            ],
            "remediation": (
                "Remove the DisableAntiSpyware=1 override under HKLM\\SOFTWARE"
                "\\Microsoft\\Windows Defender\\Real-Time Protection so Defender "
                "antivirus real-time scanning runs, or deploy a supported AV that "
                "reports into central management."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
                "DisableAntiSpyware",
                {"equals": 1},
            ),
        },
        {
            "id": "HOST-FW-PUBLIC-001",
            "title": "Host firewall public profile disabled",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 1,
            "severity": "HIGH",
            "tierSeverity": {"3": "CRITICAL"},
            "controls": [
                {"framework": "800-171", "ref": "3.13.6"},
                {"framework": "SOC2", "ref": "CC6.6"},
                {"framework": "CIS", "ref": "v8-4.6"},
            ],
            "remediation": (
                "Enable the public-profile host firewall: set EnableFirewall=1 under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters"
                "\\FirewallPolicy\\PublicProfile."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
                r"\FirewallPolicy\PublicProfile",
                "EnableFirewall",
                {"equals": 0},
            ),
        },
        {
            "id": "HOST-RDP-ENABLED-001",
            "title": "Remote Desktop (RDP) enabled",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 1,
            "severity": "MEDIUM",
            "tierSeverity": {"2": "HIGH", "3": "HIGH"},
            "controls": [
                {"framework": "800-171", "ref": "3.1.12"},
                {"framework": "SOC2", "ref": "CC6.1"},
            ],
            "remediation": (
                "Disable RDP where not required by setting fDenyTSConnections=1 "
                "under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server; "
                "where RDP is required, restrict it to NLA-only behind a VPN with "
                "tiered admin accounts."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                "fDenyTSConnections",
                {"equals": 0},
            ),
        },
        {
            "id": "HOST-OS-EOL-001",
            "title": "Windows build older than supported minimum",
            "domain": "patching",
            "platforms": ["WINDOWS"],
            "minTier": 1,
            "severity": "HIGH",
            "tierSeverity": {"3": "CRITICAL"},
            "controls": [
                {"framework": "800-171", "ref": "3.14.1"},
                {"framework": "SOC2", "ref": "CC7.1"},
                {"framework": "CIS", "ref": "v8-7.3"},
            ],
            "remediation": (
                "Upgrade endpoints below the minimum supported build "
                "(10.0.19045) to a patched in-support Windows release; isolate "
                "any exception on a compensating-control segment until upgraded."
            ),
            "detector": {
                "type": "os-version",
                "platforms": ["WINDOWS"],
                "minVersion": "10.0.19045",
            },
        },
        # ---------------- Tier 2 - Hardened --------------------------------
        {
            "id": "HOST-SCREENLOCK-001",
            "title": "Interactive screen-lock inactivity timeout absent or too loose",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "MEDIUM",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.1.10"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-4.3"},
            ],
            "remediation": (
                "Enforce machine-policy inactivity lock at 900 seconds or less: "
                "set InactivityTimeoutSecs=900 under HKLM\\SOFTWARE\\Microsoft"
                "\\Windows\\CurrentVersion\\Policies\\System via GPO."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "InactivityTimeoutSecs",
                {"notEquals": 900},
            ),
        },
        {
            "id": "HOST-AUDITPOL-001",
            "title": "Advanced audit policy not deployed on host",
            "domain": "logging",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.3.1"},
                {"framework": "SOC2", "ref": "CC7.2"},
                {"framework": "CIS", "ref": "v8-8.2"},
            ],
            "remediation": (
                "Deploy an advanced audit policy GPO so the deployed audit CSV "
                "exists at %windir%\\System32\\GroupPolicy\\Machine\\Microsoft"
                "\\Windows NT\\Audit\\audit.csv covering logon, account "
                "management, and process-creation subcategories."
            ),
            "detector": _fp(
                [r"%windir%\System32\GroupPolicy\Machine\Microsoft\Windows NT"
                 r"\Audit\audit.csv"],
                content_regex="Subcategory",
                require_match=True,
            ),
        },
        {
            "id": "HOST-LAPS-001",
            "title": "Local administrator password rotation (LAPS) not enforced",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.5.2"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-5.2"},
            ],
            "remediation": (
                "Deploy LAPS and enable its policy so AdmPwdEnabled=1 under "
                "HKLM\\Software\\Policies\\Microsoft Services\\AdmPwd, giving "
                "each endpoint a unique, rotated local-admin password."
            ),
            "detector": _reg(
                r"HKLM\Software\Policies\Microsoft Services\AdmPwd",
                "AdmPwdEnabled",
                {"notEquals": 1},
            ),
        },
        {
            "id": "HOST-PSEXEC-UNRESTRICTED-001",
            "title": "PowerShell execution policy set to Unrestricted",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {"3": "CRITICAL"},
            "controls": [
                {"framework": "800-171", "ref": "3.4.7"},
                {"framework": "SOC2", "ref": "CC8.1"},
                {"framework": "CIS", "ref": "v8-2.6"},
            ],
            "remediation": (
                "Set the machine-wide execution policy to RemoteSigned (or "
                "AllSigned) at HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds"
                "\\Microsoft.PowerShell\\ExecutionPolicy instead of Unrestricted."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
                "ExecutionPolicy",
                {"equals": "Unrestricted"},
            ),
        },
        {
            "id": "HOST-AUTORUN-USERPATH-001",
            "title": "Executables auto-starting from user-writable startup folders",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "MEDIUM",
            "tierSeverity": {"3": "HIGH"},
            "controls": [
                {"framework": "800-171", "ref": "3.4.8"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-2.6"},
            ],
            "remediation": (
                "Remove unsigned executables from per-user Startup folders "
                "(%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup) "
                "and block user-writable autorun locations via application control."
            ),
            "detector": _fp(
                [
                    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\**",
                    r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu"
                    r"\Programs\Startup\**",
                ],
                max_depth=3,
            ),
        },
        {
            "id": "HOST-UAC-DISABLED-001",
            "title": "User Account Control (EnableLUA) disabled",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.1.5"},
                {"framework": "SOC2", "ref": "CC6.3"},
                {"framework": "CIS", "ref": "v8-5.4"},
            ],
            "remediation": (
                "Re-enable UAC by setting EnableLUA=1 under HKLM\\SOFTWARE"
                "\\Microsoft\\Windows\\CurrentVersion\\Policies\\System and keep "
                "consent-prompt elevation for administrators; reboot to apply."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA",
                {"equals": 0},
            ),
        },
        {
            "id": "HOST-LATF-001",
            "title": "UAC remote token filter disabled (LocalAccountTokenFilterPolicy)",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.1.1"},
                {"framework": "SOC2", "ref": "CC6.3"},
                {"framework": "CIS", "ref": "v8-5.4"},
            ],
            "remediation": (
                "Remove LocalAccountTokenFilterPolicy=1 under HKLM\\SOFTWARE"
                "\\Microsoft\\Windows\\CurrentVersion\\Policies\\System so remote "
                "logons with local accounts receive a filtered (non-admin) token, "
                "curbing lateral-movement with captured local credentials."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "LocalAccountTokenFilterPolicy",
                {"equals": 1},
            ),
        },
        {
            "id": "HOST-NLA-DISABLED-001",
            "title": "RDP Network Level Authentication (NLA) disabled",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.1.12"},
                {"framework": "SOC2", "ref": "CC6.6"},
            ],
            "remediation": (
                "Require NLA for RDP by setting UserAuthentication=1 under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
                "\\WinStations\\RDP-Tcp."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"
                r"\RDP-Tcp",
                "UserAuthentication",
                {"equals": 0},
            ),
        },
        {
            "id": "HOST-FW-DOMAIN-001",
            "title": "Host firewall domain profile disabled",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "MEDIUM",
            "tierSeverity": {"3": "HIGH"},
            "controls": [
                {"framework": "800-171", "ref": "3.13.6"},
                {"framework": "SOC2", "ref": "CC6.6"},
                {"framework": "CIS", "ref": "v8-4.6"},
            ],
            "remediation": (
                "Enable the domain-profile host firewall: set EnableFirewall=1 "
                "under HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess"
                "\\Parameters\\FirewallPolicy\\DomainProfile."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
                r"\FirewallPolicy\DomainProfile",
                "EnableFirewall",
                {"equals": 0},
            ),
        },
        {
            "id": "HOST-REMREG-001",
            "title": "Remote Registry service running",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 2,
            "severity": "LOW",
            "tierSeverity": {"3": "MEDIUM"},
            "controls": [
                {"framework": "800-171", "ref": "3.4.8"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-4.8"},
            ],
            "remediation": (
                "Set the RemoteRegistry service (RemoteRegistry) startup type to "
                "Disabled unless a documented management process requires it."
            ),
            "detector": {
                "type": "service",
                "platforms": ["WINDOWS"],
                "name": "RemoteRegistry",
                "expectRunning": False,
            },
        },
        # ---------------- Tier 3 - Advanced --------------------------------
        {
            "id": "HOST-APPLOCKER-001",
            "title": "No AppLocker application-control policy present",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 3,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-172", "ref": "3.4.2e"},
                {"framework": "800-171", "ref": "3.4.7"},
                {"framework": "CIS", "ref": "v8-2.4"},
            ],
            "remediation": (
                "Author and deploy an AppLocker policy (audited first, then "
                "enforced) so compiled rules exist under %windir%\\System32"
                "\\AppLocker; start with allow-listing standard user-writable-"
                "path denials."
            ),
            "detector": _fp(
                [r"%windir%\System32\AppLocker*"],
                require_match=True,
            ),
        },
        {
            "id": "HOST-CREDGUARD-001",
            "title": "Credential Guard not enabled",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 3,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.5.2"},
                {"framework": "SOC2", "ref": "CC6.1"},
            ],
            "remediation": (
                "Enable Credential Guard by setting LsaCfgFlags=2 under "
                "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (UEFI-locked where "
                "hardware supports it) so credential material is virtualized away "
                "from LSASS scraping."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "LsaCfgFlags",
                {"notEquals": 2},
            ),
        },
        {
            "id": "HOST-LLMNR-001",
            "title": "LLMNR name-resolution poisoning surface enabled",
            "domain": "hardening",
            "platforms": ["WINDOWS"],
            "minTier": 3,
            "severity": "MEDIUM",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.13.6"},
                {"framework": "SOC2", "ref": "CC6.6"},
                {"framework": "CIS", "ref": "v8-12.1"},
            ],
            "remediation": (
                "Disable LLMNR via policy: set EnableMulticast=0 under "
                "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient "
                "(disable NBT-NS alongside it) to remove responder-poisoning risk."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                "EnableMulticast",
                {"notEquals": 0},
            ),
        },
        {
            "id": "HOST-WINRM-BASIC-001",
            "title": "WinRM allows Basic authentication",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 3,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.13.8"},
                {"framework": "SOC2", "ref": "CC6.7"},
            ],
            "remediation": (
                "Disallow WinRM Basic auth by setting AllowBasic=0 under "
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN"
                "\\Service; use Kerberos/HTTPS listeners only."
            ),
            "detector": _reg(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service",
                "AllowBasic",
                {"equals": 1},
            ),
        },
        {
            "id": "HOST-RDP-SECLAYER-001",
            "title": "RDP security layer below NLA/TLS-only",
            "domain": "auth",
            "platforms": ["WINDOWS"],
            "minTier": 3,
            "severity": "MEDIUM",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.13.8"},
                {"framework": "SOC2", "ref": "CC6.7"},
            ],
            "remediation": (
                "Set SecurityLayer=2 under HKLM\\SYSTEM\\CurrentControlSet"
                "\\Control\\Terminal Server\\WinStations\\RDP-Tcp so RDP negotiates "
                "TLS and requires NLA, dropping legacy RDP-security-layer fallback."
            ),
            "detector": _reg(
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"
                r"\RDP-Tcp",
                "SecurityLayer",
                {"lt": 2},
            ),
        },
        # ---------------- Cross-platform Linux -----------------------------
        {
            "id": "HOST-SSHD-AUTH-001",
            "title": "sshd permits root login or password authentication",
            "domain": "auth",
            "platforms": ["LINUX"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.1.12"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-4.6"},
            ],
            "remediation": (
                "In /etc/ssh/sshd_config set PermitRootLogin no and "
                "PasswordAuthentication no (key-based auth only), then reload "
                "sshd."
            ),
            "detector": {
                "type": "file-pattern",
                "platforms": ["LINUX"],
                "paths": ["/etc/ssh/sshd_config"],
                "contentRegex": (
                    "(?im)^\\s*(PermitRootLogin\\s+(?:yes|prohibit-password)"
                    "|PasswordAuthentication\\s+yes)"
                ),
            },
        },
        {
            "id": "HOST-WWPATH-001",
            "title": "World-writable files under system executable paths",
            "domain": "hardening",
            "platforms": ["LINUX"],
            "minTier": 2,
            "severity": "HIGH",
            "tierSeverity": {},
            "controls": [
                {"framework": "800-171", "ref": "3.4.2"},
                {"framework": "SOC2", "ref": "CC6.1"},
                {"framework": "CIS", "ref": "v8-3.3"},
            ],
            "remediation": (
                "Find world-writable executables in system PATH directories "
                "(find /usr/local/bin /usr/local/sbin /opt -perm -o+w -type f) "
                "and chmod o-w / chown them to root; monitor for regressions."
            ),
            "detector": {
                "type": "file-pattern",
                "platforms": ["LINUX"],
                "paths": ["/usr/local/bin/**", "/usr/local/sbin/**", "/opt/**"],
                "maxDepth": 6,
            },
        },
    ]


# --- validation ------------------------------------------------------------


def _check_violation(det: dict, problems: list, label: str) -> None:
    viol = det.get("violation")
    if not isinstance(viol, dict) or len(viol) != 1:
        problems.append(f"{label}: violation must be a single-operator object")
        return
    op, val = next(iter(viol.items()))
    if op not in VIOLATION_OPS:
        problems.append(f"{label}: unknown violation operator {op!r}")
        return
    if op in ("equals", "notEquals"):
        if not isinstance(val, (int, float, str)) or isinstance(val, bool):
            problems.append(f"{label}: violation.{op} must be number or string")
    elif not isinstance(val, (int, float)) or isinstance(val, bool):
        problems.append(f"{label}: violation.{op} must be numeric")


def validate_detector(rule: dict, problems: list) -> None:
    det = rule.get("detector")
    rid = rule.get("id", f"rule[{rule.get('_index', '?')}]")
    label = f"{rid}: detector"
    if not isinstance(det, dict):
        problems.append(f"{label}: must be an object")
        return
    dtype = det.get("type")
    platforms = det.get("platforms")
    if dtype not in DETECTOR_TYPES:
        problems.append(f"{label}: type {dtype!r} not in {sorted(DETECTOR_TYPES)}")
        return
    if not isinstance(platforms, list) or not platforms or not set(
        platforms
    ) <= PLATFORMS:
        problems.append(
            f"{label}: platforms must be a non-empty subset of {sorted(PLATFORMS)}"
        )
        return
    if not set(platforms) <= set(rule.get("platforms") or []):
        problems.append(f"{label}: detector platforms exceed rule platforms")
        return
    if dtype == "registry":
        key = det.get("key")
        if not isinstance(key, str) or not key.startswith(("HKLM\\", "HKCU\\")):
            problems.append(f"{label}: registry key must start HKLM\\ or HKCU\\")
        if not isinstance(det.get("value"), str) or not det["value"]:
            problems.append(f"{label}: value must be a non-empty string")
        _check_violation(det, problems, label)
    elif dtype == "file-pattern":
        paths = det.get("paths")
        if not isinstance(paths, list) or not paths or not all(
            isinstance(p, str) and p.strip() for p in paths
        ):
            problems.append(f"{label}: paths must be a non-empty list of globs")
        rx = det.get("contentRegex")
        if rx is not None:
            try:
                re.compile(rx)
            except re.error as exc:
                problems.append(f"{label}: contentRegex does not compile ({exc})")
        depth = det.get("maxDepth")
        if depth is not None and (not isinstance(depth, int) or isinstance(depth, bool)
                                  or depth < 1):
            problems.append(f"{label}: maxDepth must be a positive integer")
        req = det.get("requireMatch", False)
        if not isinstance(req, bool):
            problems.append(f"{label}: requireMatch must be a boolean")
    elif dtype == "service":
        if not isinstance(det.get("name"), str) or not det["name"]:
            problems.append(f"{label}: service name must be a non-empty string")
        if not isinstance(det.get("expectRunning"), bool):
            problems.append(f"{label}: expectRunning must be a boolean")
    elif dtype == "os-version":
        mv = det.get("minVersion")
        if not isinstance(mv, str) or not OS_VERSION_RE.match(mv):
            problems.append(f"{label}: minVersion must look like '10.0.19045'")


def validate_rules(rules: list) -> list:
    problems = []
    seen_ids = set()
    for idx, rule in enumerate(rules):
        rid = rule.get("id") or f"<rule index {idx}>"
        prefix = f"rule[{idx}] {rid}"
        for field in (
            "id", "title", "domain", "platforms", "minTier", "severity",
            "tierSeverity", "controls", "remediation", "detector",
        ):
            if field not in rule:
                problems.append(f"{prefix}: missing required field {field!r}")
        if rule.get("id") in seen_ids:
            problems.append(f"{prefix}: duplicate rule id")
        if isinstance(rule.get("id"), str):
            seen_ids.add(rule["id"])
        if not RULE_ID_RE.match(str(rule.get("id", ""))):
            problems.append(f"{prefix}: id must match HOST-<DOMAIN>-NNN format")
        if rule.get("domain") not in DOMAINS:
            problems.append(f"{prefix}: domain {rule.get('domain')!r} invalid")
        platforms = rule.get("platforms")
        if not isinstance(platforms, list) or not platforms or not set(
            platforms
        ) <= PLATFORMS:
            problems.append(
                f"{prefix}: platforms must be a non-empty subset of "
                f"{sorted(PLATFORMS)}"
            )
        mt = rule.get("minTier")
        if mt not in TIER_MINIMUMS or isinstance(mt, bool):
            problems.append(f"{prefix}: minTier must be one of 1|2|3")
        sev = rule.get("severity")
        if sev not in SEVERITIES:
            problems.append(f"{prefix}: severity {sev!r} not in severity vocabulary")
        ts = rule.get("tierSeverity")
        if not isinstance(ts, dict):
            problems.append(f"{prefix}: tierSeverity must be an object")
        else:
            for k, v in ts.items():
                if k not in {"1", "2", "3"} or v not in SEVERITIES:
                    problems.append(
                        f"{prefix}: tierSeverity entry {k!r}:{v!r} invalid"
                    )
        controls = rule.get("controls")
        if not isinstance(controls, list) or not controls:
            problems.append(f"{prefix}: controls must contain at least one entry")
        else:
            for c in controls:
                if (
                    not isinstance(c, dict)
                    or not isinstance(c.get("framework"), str)
                    or not isinstance(c.get("ref"), str)
                    or not c.get("ref")
                ):
                    problems.append(
                        f"{prefix}: control entries need framework+ref strings"
                    )
        if not isinstance(rule.get("remediation"), str) or not rule["remediation"]:
            problems.append(f"{prefix}: remediation must be a non-empty string")
        validate_detector(rule, problems)
    return problems


def validate_pack_shape(pack: dict) -> list:
    problems = []
    if pack.get("schema") != SCHEMA:
        problems.append(f"pack.schema must equal {SCHEMA!r}")
    if pack.get("packId") != PACK_ID:
        problems.append(f"pack.packId must equal {PACK_ID!r}")
    version = str(pack.get("version", ""))
    if not VERSION_RE.match(version):
        problems.append("pack.version must be date-based like '2026.08.0'")
    if pack.get("channel") not in {"stable", "beta"}:
        problems.append("pack.channel must be 'stable' or 'beta'")
    if pack.get("minAgentVersion") != MIN_AGENT_VERSION:
        problems.append(f"pack.minAgentVersion must equal {MIN_AGENT_VERSION!r}")
    created = pack.get("createdAt")
    if not isinstance(created, str) or not _parse_rfc3339(created):
        problems.append("pack.createdAt must be RFC3339 (e.g. 2026-08-25T00:00:00Z)")
    return problems


def _parse_rfc3339(value: str):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate_distribution(pack: dict, problems: list) -> None:
    counts = {1: 0, 2: 0, 3: 0}
    linux_rules = 0
    for rule in pack["rules"]:
        mt = rule.get("minTier")
        if mt in counts:
            counts[mt] += 1
        if "LINUX" in rule.get("platforms", []):
            linux_rules += 1
    for tier, minimum in sorted(TIER_MINIMUMS.items()):
        if counts[tier] < minimum:
            problems.append(
                f"distribution: tier {tier} needs >= {minimum} rules, found "
                f"{counts[tier]}"
            )
    if linux_rules < LINUX_MIN_RULES:
        problems.append(
            f"distribution: needs >= {LINUX_MIN_RULES} LINUX-platform rules, "
            f"found {linux_rules}"
        )


# --- rendering / writing ---------------------------------------------------


def build_pack(version: str, channel: str, created_at: str) -> dict:
    return {
        "schema": SCHEMA,
        "packId": PACK_ID,
        "version": version,
        "channel": channel,
        "minAgentVersion": MIN_AGENT_VERSION,
        "createdAt": created_at,
        "rules": _rules(),
    }


def render_bytes(obj: dict) -> bytes:
    return (json.dumps(obj, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(tmp_name, str(path))
    except BaseException:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def build_manifest(pack: dict) -> dict:
    tier_counts = {str(t): 0 for t in sorted(TIER_MINIMUMS)}
    domains = {}
    detectors = {}
    platforms = set()
    for rule in pack["rules"]:
        tier_counts[str(rule["minTier"])] += 1
        domains[rule["domain"]] = domains.get(rule["domain"], 0) + 1
        dtype = rule["detector"]["type"]
        detectors[dtype] = detectors.get(dtype, 0) + 1
        platforms.update(rule["platforms"])
    return {
        "schema": SCHEMA,
        "packId": pack["packId"],
        "version": pack["version"],
        "channel": pack["channel"],
        "createdAt": pack["createdAt"],
        "ruleCount": len(pack["rules"]),
        "minTierCounts": tier_counts,
        "domainCounts": dict(sorted(domains.items())),
        "detectorTypeCounts": dict(sorted(detectors.items())),
        "platforms": sorted(platforms),
        "notes": (
            "Seed catalog authored by AuditForge scripts/build_rulepack.py; "
            "rule ids are stable forever - behavior changes ship as new ids."
        ),
    }


def run(out_dir: Path, version: str, channel: str, created_at: str) -> int:
    pack = build_pack(version, channel, created_at)
    problems = validate_pack_shape(pack)
    problems.extend(validate_rules(pack["rules"]))
    validate_distribution(pack, problems)
    if problems:
        print(f"ERROR: rule-pack validation failed with {len(problems)} problem(s):",
              file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 2

    pack_bytes = render_bytes(pack)
    digest = hashlib.sha256(pack_bytes).hexdigest()

    version_dir = out_dir / version
    atomic_write(version_dir / "pack.json", pack_bytes)
    atomic_write(version_dir / "manifest.json", render_bytes(build_manifest(pack)))

    pointer = {
        "packId": PACK_ID,
        "channel": channel,
        "version": version,
        "sha256": digest,
        "sizeBytes": len(pack_bytes),
        "updatedAt": created_at,
    }
    atomic_write(out_dir / "channels" / f"{channel}.json", render_bytes(pointer))

    print(f"pack     {version_dir / 'pack.json'}  sha256={digest}  "
          f"size={len(pack_bytes)}B")
    print(f"pointer  {out_dir / 'channels' / (channel + '.json')} -> "
          f"{version} ({channel})")
    print(f"rules    {len(pack['rules'])} "
          f"(tiers: " + ", ".join(
              f"T{t}={sum(1 for r in pack['rules'] if r['minTier'] == t)}"
              for t in sorted(TIER_MINIMUMS)
          ) + ")")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the Ronin core posture rule pack.",
    )
    parser.add_argument("--out", required=True,
                        help="output root, e.g. Z:\\roninai\\artifacts\\agent"
                             "\\rulepacks")
    parser.add_argument("--version", default=DEFAULT_VERSION,
                        help=f"pack version (default {DEFAULT_VERSION})")
    parser.add_argument("--channel", default=DEFAULT_CHANNEL,
                        choices=["stable", "beta"],
                        help=f"channel (default {DEFAULT_CHANNEL})")
    parser.add_argument("--created-at", default=DEFAULT_CREATED_AT,
                        dest="created_at",
                        help="RFC3339 timestamp baked into the pack (default "
                             f"{DEFAULT_CREATED_AT}); fixes byte output")
    args = parser.parse_args(argv)

    if not _parse_rfc3339(args.created_at):
        parser.error(f"--created-at must be RFC3339, got {args.created_at!r}")
    if not VERSION_RE.match(args.version):
        parser.error(f"--version must look like '{DEFAULT_VERSION}', got "
                     f"{args.version!r}")
    return run(Path(args.out).resolve(), args.version, args.channel,
               args.created_at)


if __name__ == "__main__":
    sys.exit(main())
