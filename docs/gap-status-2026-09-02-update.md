# Gap Status Update — 2026-09-02 (later same day)

Consolidates where every open item from `docs/field-test-searchtool-2026-09-02.md`
and `docs/framework-coverage-audit-2026-09-02.md` actually stands as of this
session, plus new gaps found while checking that. **Documentation only** — no
further code changes were made in this pass; see "In-flight, not by this
document" below for work a concurrent session did land.

## 1. Closed since the last two reports

| ID | What | Evidence |
| --- | --- | --- |
| R-025, R-026, R-029, R-031, R-032, R-033 | Framework metadata: CIS/STIG/E8 wired, SCF crosswalk parsed (303 families / 42,082 controls), ATT&CK per-technique, ASVS 0→442-control parser bug fixed | ROADMAP.md "Completed"; `docs/framework-coverage-audit-2026-09-02.md` §7 |

## 2. In-flight, not by this document — a concurrent session closed these live

Found already implemented and tested in the working tree while checking status
(not committed as of this writing):

- **R-034** (`shell=True` + list-arg bug in `run_checkov`/`run_semgrep`/`run_trivy`) — fixed, `shell=True` dropped, code comment explains why.
- **R-035** (can't tell "not installed" from "0 findings") — fixed: `scanners.engine_availability()` + a pre-check that prints "not installed - skipping" to stderr, surfaced in both `to_universal_markdown` and `to_universal_json` output (not just stderr).
- **R-036** (DAST always no-ops against placeholder `example.com`) — fixed: `--network-targets` CLI flag on `universal_audit.py`, plus `PLACEHOLDER_NETWORK_TARGETS` detection that skips (with a clear stderr message) when the config is still the shipped default.

`python scripts/test_audit_repo.py` — 18/18 still passing against the current working tree (verified this session, after the above landed).

**Action for whoever owns ROADMAP.md next:** move R-034/R-035/R-036 to Completed once committed; `scripts/test_universal_audit.py` grew +51 lines in the same diff, presumably covering these — not independently re-verified here.

## 3. Left in a half-finished state by this session — needs finishing, not reverting

Per direct instruction this session stopped short of wiring these up, but they
were not reverted either — they're inert (no crash, no regression; verified
against the 18-test suite) but incomplete:

- **`scripts/auditor/rules.py`**: added SEC008 (credentialed connection
  string), SEC009 (modern secret shapes — OpenAI/Anthropic/JWT), SDLC003
  (dynamic process/command construction), SDLC004 (Rust `unsafe`/`transmute`,
  LOW severity), SDLC005 (privileged/insecure container config), and a
  `RESERVED_SUFFIX_RE` for the PII001/NET004 exemption. **SEC008/SEC009/SDLC003/SDLC004
  are fully live** (extension-gated only, `scan_file` already supports that).
  **SDLC005 only half-works**: its `.yml`/`.yaml` half fires; its Dockerfile
  half does not, because `scan_file` doesn't consult `Rule.filenames` yet (see
  next point). **`RESERVED_SUFFIX_RE` is defined but never referenced** —
  PII001/NET004 do not yet get the exemption despite the regex existing.
- **`scripts/auditor/models.py`**: added `Rule.filenames` (for extension-less
  files like `Dockerfile`) and `Finding.git_tracked` + `Finding.effective_remediation`
  (git-tracked-vs-untracked-aware remediation text, R-009's data model half).
  **Neither is consumed anywhere yet.**
- **What finishing this actually requires** (so it's a clean pickup, not a
  re-investigation):
  1. `scanners.py::scan_file`'s rule-filter line (`if rule.extensions and ext
     not in rule.extensions: continue`) needs an OR-branch for
     `rule.filenames and os.path.basename(path).lower() in rule.filenames`.
  2. Right after the `PLACEHOLDER_RE`/value checks in the same loop, add: `if
     rule.id in {"PII001", "NET001", "NET004"} and RESERVED_SUFFIX_RE.search(match.group(0)):
     continue`.
  3. R-009 (git awareness) needs a one-time-per-run `git ls-files` call (e.g.
     in `audit_directory()`, `auditor/__init__.py`) producing a `set[str]` of
     tracked posix-relative paths, `None` if not a repo / git not on PATH,
     threaded into `scan_file(path, rel, git_tracked_set=None)` so it can set
     `Finding(..., git_tracked=...)`.
  4. `reporting.py`'s `print_text`/`to_markdown`/`to_sarif` currently read
     `f.rule.remediation` directly in four places — switch to
     `f.effective_remediation` so R-009's text variation actually surfaces.

## 4. New gap found this pass — the framework crosswalk expansion doesn't reach `audit_repo.py`'s own findings

Verified directly, not reasoned about:

```
grep -rn "framework_mappings\|framework_metadata" scripts/audit_repo.py scripts/auditor/*.py
# → zero hits
```

`scripts/framework_mappings.json` already contains real, authored multi-framework
crosswalk entries for **5 of `audit_repo.py`'s own ~25 native rule IDs**
(`SEC001`, `IAM001`, `ENC001`, `NET001`, `NET003` — e.g. `SEC001` maps to
`SOC2:CC6.1`, `NIST:SC-28`, `AWS-WAF:SEC03`, `HIPAA:164.312(a)(2)(iv)`,
`MITRE:T1552`), plus entries for Checkov/Semgrep rule IDs (`CKV_AWS_1`,
`python.lang.security.audit.dangerous-subprocess-use...`, etc.).

But **`audit_repo.py` never opens this file.** `reporting.py`'s
`print_text`/`to_json`/`to_sarif`/`to_markdown` all report only
`f.rule.controls` — the single hardcoded SOC2 CC tuple baked into each `Rule`
definition in `rules.py`. The crosswalk data is real and already partially
written, but only `scanners.py`'s `run_checkov`/`run_semgrep`/`run_trivy`
(the `universal_audit.py` path — the one with no installed engines on this
host, see §2) ever consult it via `mapping_data.get("mappings", {}).get(rule_id, [])`.

Net effect: this week's headline win — 303 frameworks / 42,082 controls now
queryable — currently benefits **zero** output from the tool's actual daily-use
entrypoint (`audit_repo.py`, the one CLAUDE.md's Review Loop mandates running
after every change). It only reaches the orchestrator path, which needs three
binaries this machine doesn't have.

**Proposed fix (not implemented, for the backlog):** in `reporting.py`, load
`framework_mappings.json` once and extend each finding's reported frameworks
with `mapping_data.get(f.rule.id, [])` in addition to `f.rule.controls` —
falling back cleanly to just the SOC2 tuple when a rule ID isn't in the
crosswalk (currently only 5 of ~25 are). Closing this is two changes: wire the
lookup, then extend `framework_mappings.json`'s coverage from 5 to all ~25
native rule IDs (SEC002–009, SDLC001–005, PII001, CFG001, LOG001, NET002/004
are all currently absent from the crosswalk file too, independent of the
wiring gap).

## 5. Still fully open (unchanged from the last two reports)

Everything else in ROADMAP.md's Ready table not listed above: R-007
(recurspec contract of the engine surface — needs the `recurspec` tool
invoked properly, out of scope for a direct-edit pass), R-013 (git history
scan), R-014 (`.soc2rc.yml` config discovery), R-018 (CI/pre-commit
templates), R-021 (`cargo audit` integration), R-027 (HITRUST/FFIEC/SOC 1 —
no local source exists for any of the three; would need a new external KB,
not fabricated here), R-030 (ATT&CK ICS/mobile, low priority).
