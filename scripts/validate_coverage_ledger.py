#!/usr/bin/env python3
"""Validates coverage-ledger.json (ported from the MIT-licensed
validate-coverage-ledger.cjs to stdlib Python so AuditForge runs have no
Node.js dependency).

Usage: python scripts/validate_coverage_ledger.py <coverage-ledger.json>
Exit 0 on PASS, 1 with up to 100 errors on failure.

Enforced (same core contracts as the .cjs):
  - 5 MiB input cap, <=10000 units, top-level array
  - 16 required fields per unit; status/prior_status enums
  - coverage_id uniqueness + canonical RFC 3986 encoding of canonical_refs
    (surface::boundary::subsystem::attack_class[::lifecycle])
  - agent_id shape + Windows-reserved names; fingerprint shapes
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import json as _json

MAX_BYTES = 5 * 1024 * 1024
MAX_UNITS = 10000
MAX_ERRORS = 100

REQUIRED_FIELDS = [
    "coverage_id", "canonical_refs", "surface", "boundary", "subsystem",
    "attack_class", "starting_paths", "ordinary_attack_class_block",
    "selected_companion_blocks", "excluded_blocks", "prior_status",
    "attempts", "wave", "status", "agent_id", "reviewed_paths",
    "local_checks", "result_fingerprints", "unresolved",
]
STATUSES = {"planned", "not_applicable", "out_of_scope", "in_progress",
            "covered", "candidate", "blocked", "deferred"}
PRIOR_STATUSES = {"new", "prior_confirmed_same_source",
                   "prior_confirmed_changed_source",
                   "prior_needs_validation", "prior_deferred",
                   "prior_blocked", "prior_out_of_scope",
                   "prior_covered_same_source",
                   "prior_covered_changed_source",
                   "prior_rejected_claim_changed", "none"}
ATTEMPT_STATUSES = {"covered", "candidate", "blocked"}
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
WINDOWS_RESERVED_AGENT = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$")
UNRESERVED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                 "0123456789-._~")


def encode_ref(value: str) -> str:
    out = []
    for ch in value:
        if ch in UNRESERVED:
            out.append(ch)
        else:
            for byte in ch.encode("utf-8"):
                out.append(f"%{byte:02X}")
    return "".join(out)


def canonical_id(refs: dict) -> str | None:
    parts = []
    for key in ("surface", "boundary", "subsystem", "attack_class"):
        value = refs.get(key)
        if not isinstance(value, str) or not value.strip():
            return None
        parts.append(encode_ref(value))
    lifecycle = refs.get("lifecycle")
    if lifecycle is not None:
        if not isinstance(lifecycle, str) or not lifecycle.strip():
            return None
        parts.append(encode_ref(lifecycle))
    return "::".join(parts)


class Checker:
    def __init__(self):
        self.errors: list = []
        self.seen_ids: dict = {}

    def err(self, msg: str):
        if len(self.errors) < MAX_ERRORS:
            self.errors.append(msg)

    def check_unit(self, i: int, unit):
        where = f"[{i}]"
        if not isinstance(unit, dict):
            self.err(f"{where}: must be an object")
            return
        for field in REQUIRED_FIELDS:
            if field not in unit:
                self.err(f"{where}: missing '{field}'")
        if unit.get("status") not in STATUSES:
            self.err(f"{where}: bad status {unit.get('status')!r}")
        if unit.get("prior_status") not in PRIOR_STATUSES:
            self.err(f"{where}: bad prior_status {unit.get('prior_status')!r}")
        cid = unit.get("coverage_id")
        if not isinstance(cid, str) or not cid:
            self.err(f"{where}: coverage_id must be a non-empty string")
        elif cid in self.seen_ids:
            self.err(f"{where}: duplicate coverage_id '{cid}' "
                     f"(first at [{self.seen_ids[cid]}])")
        else:
            self.seen_ids[cid] = i
        refs = unit.get("canonical_refs")
        if isinstance(refs, dict) and isinstance(cid, str):
            expected = canonical_id(refs)
            if expected is None:
                self.err(f"{where}: canonical_refs needs non-blank "
                         f"surface/boundary/subsystem/attack_class strings")
            elif cid != expected:
                self.err(f"{where}: coverage_id is not the canonical "
                         f"encoding (expected '{expected}')")
        agent = unit.get("agent_id")
        if agent not in (None, ""):
            if not isinstance(agent, str) or not AGENT_ID_RE.match(agent) or \
                    WINDOWS_RESERVED_AGENT.match(agent):
                self.err(f"{where}: bad agent_id {agent!r}")
        for fp in unit.get("result_fingerprints", []) or []:
            if not isinstance(fp, str) or not FINGERPRINT_RE.match(fp):
                self.err(f"{where}: bad result fingerprint {fp!r}")
        for key in ("starting_paths", "reviewed_paths"):
            val = unit.get(key)
            if val is not None and not isinstance(val, list):
                self.err(f"{where}: '{key}' must be an array")
        attempts = unit.get("attempts", [])
        if not isinstance(attempts, list):
            self.err(f"{where}: attempts must be an array")
            return
        for j, attempt in enumerate(attempts):
            loc = f"{where}.attempts[{j}]"
            if not isinstance(attempt, dict):
                self.err(f"{loc}: must be an object")
                continue
            if attempt.get("status") not in ATTEMPT_STATUSES:
                self.err(f"{loc}: bad status {attempt.get('status')!r}")


def validate_file(path: str) -> list:
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BYTES:
        return [f"input exceeds {MAX_BYTES} byte cap"]
    try:
        data = _json.loads(raw)
    except _json.JSONDecodeError as exc:
        return [f"invalid JSON: {exc}"]
    if not isinstance(data, list):
        return ["top level must be an array of coverage units"]
    if len(data) > MAX_UNITS:
        return [f"too many units ({len(data)} > {MAX_UNITS})"]
    checker = Checker()
    for i, unit in enumerate(data):
        checker.check_unit(i, unit)
        if len(checker.errors) >= MAX_ERRORS:
            break
    return checker.errors


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate coverage-ledger.json.")
    parser.add_argument("ledger", help="Path to coverage-ledger.json")
    args = parser.parse_args(argv)
    errors = validate_file(args.ledger)
    if errors:
        print(f"FAIL {args.ledger}: {len(errors)} error(s)", file=sys.stderr)
        for e in errors[:MAX_ERRORS]:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"PASS {args.ledger}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
