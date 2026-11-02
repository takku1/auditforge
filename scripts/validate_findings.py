#!/usr/bin/env python3
"""Validates findings.json against the Cloudflare security-audit skill's
verdict contracts (ported from the MIT-licensed validate-findings.cjs to
stdlib Python so AuditForge runs have no Node.js dependency).

Usage: python scripts/validate_findings.py <findings.json>
Exit 0 on PASS, 1 with up to 100 errors on failure.

Enforced (same core contracts as the .cjs):
  - 5 MiB input cap, <=1000 top-level findings, nesting depth <=64
  - top-level array; every record matches exactly one verdict branch
  - confirmed: verdict/fingerprint/title/description/root_cause/
    intended_behavior/trace/evidence/conditions/execution/remediation/
    severity/confidence; no severity on the other branches
  - needs_validation: claimed_root_cause/trace/evidence/blockers/
    validation_plan (local and/or deployment); no severity/execution
  - rejected: claimed_root_cause/trace/evidence/reason
  - additionalProperties rejected everywhere; fingerprint shape;
    trace ordering (entrypoint first, sink last, propagation between);
    condition kinds; overall severity never exceeds demonstrated impact
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024
MAX_FINDINGS = 1000
MAX_DEPTH = 64
MAX_ERRORS = 100

FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
VISIBLE_RE = re.compile(r"[^\s]")

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3,
                 "critical": 4}
CONFIDENCE = {"low", "medium", "high"}
CONDITION_KINDS = {"authentication_level", "authorization_role",
                   "user_interaction", "system_configuration",
                   "network_routing", "environmental_dependency",
                   "data_state", "timing_dependency",
                   "third_party_dependency"}

BASE_REQUIRED = ["verdict", "fingerprint", "title", "description"]
BASE_TEXT = ["title", "description"]

CONFIRMED_REQUIRED = BASE_REQUIRED + ["root_cause", "intended_behavior",
                                      "trace", "evidence", "conditions",
                                      "execution", "remediation", "severity",
                                      "confidence"]
CONFIRMED_FORBIDDEN = ["claimed_root_cause", "blockers",
                       "validation_plan", "reason"]
CONFIRMED_TEXT = BASE_TEXT + ["root_cause", "intended_behavior"]

NEEDS_REQUIRED = BASE_REQUIRED + ["claimed_root_cause", "trace",
                                  "evidence", "blockers", "validation_plan"]
NEEDS_FORBIDDEN = ["root_cause", "intended_behavior", "execution",
                   "remediation", "severity", "confidence", "reason"]
NEEDS_TEXT = BASE_TEXT + ["claimed_root_cause"]

REJECTED_REQUIRED = BASE_REQUIRED + ["claimed_root_cause", "trace",
                                     "evidence", "reason"]
REJECTED_FORBIDDEN = ["root_cause", "intended_behavior", "execution",
                      "remediation", "severity", "confidence", "blockers",
                      "validation_plan"]
REJECTED_TEXT = BASE_TEXT + ["claimed_root_cause", "reason"]


class Checker:
    def __init__(self):
        self.errors: list = []

    def err(self, msg: str):
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(msg)

    def check_visible(self, where: str, value, fields: list):
        if not isinstance(value, dict):
            return
        for f in fields:
            v = value.get(f)
            if not isinstance(v, str) or not VISIBLE_RE.search(v):
                self.err(f"{where}: field '{f}' must be non-blank text")

    def check_trace(self, where: str, trace):
        if not isinstance(trace, list) or not trace:
            self.err(f"{where}: trace must be a non-empty array")
            return
        seen = set()
        for i, step in enumerate(trace):
            loc = f"{where}.trace[{i}]"
            if not isinstance(step, dict):
                self.err(f"{loc}: must be an object")
                continue
            kind = step.get("kind")
            if kind not in ("entrypoint", "propagation", "sink"):
                self.err(f"{loc}: bad kind '{kind}'")
            for req in ("kind", "file", "line", "scope", "description"):
                if req not in step:
                    self.err(f"{loc}: missing '{req}'")
            extra = set(step) - {"kind", "file", "line", "scope", "description"}
            if extra:
                self.err(f"{loc}: extra keys {sorted(extra)}")
            if not isinstance(step.get("line"), int) or step.get("line", 0) < 1:
                self.err(f"{loc}: line must be an integer >= 1")
            key = (kind, step.get("file"), step.get("line"))
            if key in seen:
                self.err(f"{loc}: duplicate trace step")
            seen.add(key)
        kinds = [s.get("kind") for s in trace if isinstance(s, dict)]
        if len(kinds) == 1:
            if kinds[0] not in ("entrypoint", "sink"):
                self.err(f"{where}: single-step trace must be entrypoint or sink")
        elif kinds:
            if kinds[0] != "entrypoint":
                self.err(f"{where}: trace must start with entrypoint")
            if kinds[-1] != "sink":
                self.err(f"{where}: trace must end with sink")
            if any(k not in ("entrypoint", "propagation", "sink") for k in kinds):
                pass
            elif any(k == "entrypoint" for k in kinds[1:]) or \
                    any(k == "sink" for k in kinds[:-1]):
                self.err(f"{where}: entrypoint/sink may only open/close the trace")

    def check_evidence(self, where: str, evidence):
        if not isinstance(evidence, list) or not evidence:
            self.err(f"{where}: evidence must be a non-empty array")
            return
        for i, item in enumerate(evidence):
            loc = f"{where}.evidence[{i}]"
            if not isinstance(item, dict):
                self.err(f"{loc}: must be an object")
                continue
            for req in ("file", "line", "description"):
                if req not in item:
                    self.err(f"{loc}: missing '{req}'")
            extra = set(item) - {"file", "line", "description"}
            if extra:
                self.err(f"{loc}: extra keys {sorted(extra)}")

    def check_record(self, i: int, record):
        where = f"[{i}]"
        if not isinstance(record, dict):
            self.err(f"{where}: must be an object")
            return
        verdict = record.get("verdict")
        if verdict == "confirmed":
            required, forbidden, text = (CONFIRMED_REQUIRED, CONFIRMED_FORBIDDEN,
                                         CONFIRMED_TEXT)
        elif verdict == "needs_validation":
            required, forbidden, text = (NEEDS_REQUIRED, NEEDS_FORBIDDEN,
                                         NEEDS_TEXT)
        elif verdict == "rejected":
            required, forbidden, text = (REJECTED_REQUIRED, REJECTED_FORBIDDEN,
                                         REJECTED_TEXT)
        else:
            self.err(f"{where}: verdict must be confirmed|needs_validation|"
                     f"rejected, got {verdict!r}")
            return
        for req in required:
            if req not in record:
                self.err(f"{where}: {verdict} record missing '{req}'")
        for bad in forbidden:
            if bad in record:
                self.err(f"{where}: {verdict} record must not use '{bad}'")
        extra = set(record) - set(required)
        if extra:
            self.err(f"{where}: extra keys {sorted(extra)} "
                     f"(additionalProperties is false)")
        fp = record.get("fingerprint", "")
        if not isinstance(fp, str) or not FINGERPRINT_RE.match(fp):
            self.err(f"{where}: bad fingerprint {fp!r}")
        self.check_visible(where, record, text)
        if "trace" in record:
            self.check_trace(where, record["trace"])
        if "evidence" in record:
            self.check_evidence(where, record["evidence"])
        if verdict == "confirmed":
            self._check_confirmed(where, record)
        elif verdict == "needs_validation":
            self._check_needs(where, record)

    def _check_confirmed(self, where: str, record: dict):
        conds = record.get("conditions", [])
        if not isinstance(conds, list):
            self.err(f"{where}: conditions must be an array")
        else:
            for i, c in enumerate(conds):
                if not isinstance(c, dict) or \
                        c.get("kind") not in CONDITION_KINDS:
                    self.err(f"{where}.conditions[{i}]: bad kind")
                extra = set(c or {}) - {"kind", "description"}
                if extra:
                    self.err(f"{where}.conditions[{i}]: extra keys")
        exe = record.get("execution", {})
        if not isinstance(exe, dict):
            self.err(f"{where}: execution must be an object")
            return
        for req in ("attacker_perspective", "payloads", "instructions",
                    "observed_result"):
            if req not in exe:
                self.err(f"{where}.execution: missing '{req}'")
        extra = set(exe) - {"attacker_perspective", "payloads",
                            "instructions", "observed_result"}
        if extra:
            self.err(f"{where}.execution: extra keys {sorted(extra)}")
        if isinstance(exe.get("payloads"), list) and not exe["payloads"]:
            self.err(f"{where}.execution: payloads must be non-empty")
        if isinstance(exe.get("instructions"), list) and not exe["instructions"]:
            self.err(f"{where}.execution: instructions must be non-empty")
        sev = record.get("severity", {})
        if not isinstance(sev, dict):
            self.err(f"{where}: severity must be an object")
            return
        for side in ("likelihood", "impact"):
            part = sev.get(side, {})
            if part.get("score") not in SEVERITY_RANK:
                self.err(f"{where}.severity.{side}: bad score")
            extra = set(part or {}) - {"score", "reason"}
            if extra:
                self.err(f"{where}.severity.{side}: extra keys")
        overall = sev.get("overall_severity")
        if overall not in SEVERITY_RANK:
            self.err(f"{where}.severity: bad overall_severity")
        else:
            impact = (sev.get("impact", {}) or {}).get("score")
            if impact in SEVERITY_RANK and \
                    SEVERITY_RANK[overall] > SEVERITY_RANK[impact]:
                self.err(f"{where}.severity: overall ({overall}) exceeds "
                         f"demonstrated impact ({impact})")
        conf = record.get("confidence", {})
        if (conf.get("score") not in CONFIDENCE) or \
                not isinstance(conf.get("reason"), str) or \
                not VISIBLE_RE.search(conf.get("reason") or ""):
            self.err(f"{where}.confidence: need score + non-blank reason")

    def _check_needs(self, where: str, record: dict):
        blockers = record.get("blockers")
        if not isinstance(blockers, list) or not blockers or \
                not all(isinstance(b, str) and VISIBLE_RE.search(b)
                        for b in blockers):
            self.err(f"{where}: blockers must be a non-empty string array")
        plan = record.get("validation_plan", {})
        if not isinstance(plan, dict):
            self.err(f"{where}: validation_plan must be an object")
            return
        extra = set(plan) - {"local", "deployment"}
        if extra:
            self.err(f"{where}.validation_plan: extra keys {sorted(extra)}")
        has_local = isinstance(plan.get("local"), str) and \
            VISIBLE_RE.search(plan["local"])
        has_deploy = isinstance(plan.get("deployment"), str) and \
            VISIBLE_RE.search(plan["deployment"])
        if not (has_local or has_deploy):
            self.err(f"{where}.validation_plan: need a non-blank local and/or "
                     f"deployment plan")


def _depth(value, seen=0) -> int:
    if isinstance(value, dict):
        return 1 + max([_depth(v) for v in value.values()] + [0])
    if isinstance(value, list):
        return 1 + max([_depth(v) for v in value] + [0])
    return 0


def validate_file(path: str) -> list:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        return [f"input exceeds {MAX_BYTES} byte cap"]
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [f"invalid JSON: {exc}"]
    if not isinstance(data, list):
        return ["top level must be an array of finding records"]
    if len(data) > MAX_FINDINGS:
        return [f"too many findings ({len(data)} > {MAX_FINDINGS})"]
    if _depth(data) > MAX_DEPTH:
        return ["nesting depth exceeds cap"]
    checker = Checker()
    for i, record in enumerate(data):
        checker.check_record(i, record)
        if len(checker.errors) >= MAX_ERRORS:
            break
    return checker.errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Validate findings.json.")
    parser.add_argument("findings", help="Path to findings.json")
    args = parser.parse_args(argv)
    errors = validate_file(args.findings)
    if errors:
        print(f"FAIL {args.findings}: {len(errors)} error(s)", file=sys.stderr)
        for e in errors[:MAX_ERRORS]:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"PASS {args.findings}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
