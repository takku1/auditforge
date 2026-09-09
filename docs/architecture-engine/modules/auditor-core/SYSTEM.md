# Auditor Core (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

The shared detection engine: regex rules tagged to SOC 2 controls
(`rules.py`), the file-walking/matching logic (`scanners.py`), the
`Finding`/`Rule`/`UnifiedFinding` data model (`models.py`), report rendering
in four formats (`reporting.py`), baseline diffing (`baseline.py`), and the
external-scanner orchestrator (`orchestrator.py`). Both CLI entrypoints
(see [cli-entrypoints](../cli-entrypoints/SYSTEM.md)) call into this package;
neither duplicates detection logic.

Does not own: argument parsing or process exit codes (cli-entrypoints'), what
frameworks exist (framework-sync's) — only which native rule IDs map to
which framework refs via `framework_mappings.json`, which this package reads
but does not generate.

## 2. Sub-System Decomposition

Atomic leaf (BUILD — pre-existing, field-tested across two documented field
tests, `docs/field-test-roninai-2026-08-25.md` and
`docs/field-test-searchtool-2026-09-02.md`).

## 3. Interface Contracts

- **Inputs:** a directory path, exclude globs, min-severity threshold, optional history-scan flag and disabled-rules set (R-013/R-014); for the orchestrator path, `config/compliance_config.yaml` and installed external binaries.
- **Outputs:** `dict` report shape (`target`, `scanned_at`, `files_scanned`, `skipped`, `summary`, `findings`) from `audit_directory()`; a `List[UnifiedFinding]` from each `run_*` orchestrator method.

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL classify every finding's severity using
  `SEVERITY_RANK`, downgrading exactly one level when `in_test_context` is
  true (`test_test_context_downgrade`).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL suppress a finding on any line containing
  the literal token `soc2-ignore` (`test_inline_suppression`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a file exceeds `MAX_FILE_BYTES` or fails a binary
  sniff THEN THE SYSTEM SHALL skip it and report the skip reason rather than
  silently returning no findings (R-017; `TestSkipTransparency`).
  - `EvidenceStage:` Sampled
- **[Event-driven]** WHEN `history=True` THE SYSTEM SHALL scan
  `git log -p --all` for added-line matches in addition to the working tree
  (R-013; `TestHistoryScan`).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL report every native rule ID's crosswalk
  entries from `framework_mappings.json` alongside its baked-in SOC2 refs
  (R-037).
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-111:** One shared `auditor` package behind two CLI entrypoints
  (`audit_repo.py` for the native regex scanner, `universal_audit.py` for
  the external-tool orchestrator), not two independent implementations —
  they share `models.py`'s `UnifiedFinding`/`Finding` and
  `reporting.py`'s crosswalk loading.
- **ADR-112:** `scan_file()` returns `(findings, skip_reason)`, not just
  `findings` (R-017) — a `None` skip_reason is the only "fully scanned, zero
  findings" signal; any other value means the file was never actually
  examined.
- **ADR-113:** History scanning (`scan_git_history`) is line-based against
  `+`-added diff lines only, not whole-file regex like `scan_file` — a
  `-`-removed line was never present as of that commit, and re-scanning
  unchanged context lines commit-after-commit would be pure noise.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/auditor/__init__.py`,
  `scripts/auditor/models.py`, `scripts/auditor/rules.py`,
  `scripts/auditor/scanners.py`, `scripts/auditor/reporting.py`,
  `scripts/auditor/orchestrator.py`, `scripts/auditor/baseline.py`,
  `scripts/test_audit_repo.py`, `scripts/test_universal_audit.py` (the two
  test files are listed here too, not just in Test Surface Seam below -
  recurspec's structure gate only exempts a file's own public symbols from
  `structure.public.uncontracted` via an Implementation Files declaration,
  Test Surface Seam alone only satisfies the separate
  `structure.test.uncontracted`/`structure.test_surface.missing` checks)
- **Test Surface Seam:** `scripts/test_audit_repo.py`, `scripts/test_universal_audit.py` (run via `python -m pytest`)

## 7. Measurement Seams

- **Primary Metric:** `pytest_pass_rate` (target: 1.0; direction: higher) —
  no dedicated `measure.ps1` exists; the pytest exit code is the real gate
  today, stated honestly rather than inventing a script that doesn't exist.
- **Evaluation Gate:** `python -m pytest scripts/test_audit_repo.py
  scripts/test_universal_audit.py` (exit 0)
- **Correctness Backpressure:** `python scripts/audit_repo.py scripts/
  --min-severity MEDIUM` (self-scan; CLAUDE.md Review Loop mandate)
- **Telemetry Surface:** none (local CLI tool, no telemetry by design —
  CLAUDE.md's PII-scrubbing mandate would apply if this changed).
- **Branching Policy:** n/a — direct commits to `main`, per existing repo
  convention (see recent `git log`).

## 8. Technology Resolution

- **Decision class:** BUILD
- **Justification:** a SOC2-control-tagged regex scanner with baseline
  diffing and four output formats is a narrow enough need, and predates this
  contract by multiple sessions (field-tested against two real external
  targets) — re-litigating BUY/ADOPT now would discard working, evidenced
  code for no evidenced gain.
- **Selected:** Python 3 stdlib (`re`, `hashlib`, `dataclasses`) + PyYAML for
  config; no scanning framework/library.
- **Standard / protocol:** SARIF 2.1.0 for one output format.
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | Semgrep/Checkov as the only engine | already used as *additional* signal via `orchestrator.py`; native rules exist because they're SOC2-control-tagged and dependency-free, which neither external tool is |
- **Fit gap:** regex-based — no AST/dataflow analysis; documented as a
  known limitation, not silently absent.
- **Seam:** `audit_directory()` / `UniversalAuditor` class boundary.
- **Exit cost:** MEDIUM — ~2500 lines across 7 files; replaceable but not
  trivial.
- **Cost model:** $0 (own compute only).
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** a scan that finds nothing is indistinguishable from "no
  problems" unless `skipped` counts and `engine_availability()` are also
  checked — this is why R-017/R-035 exist.
- **Open questions:** none.
