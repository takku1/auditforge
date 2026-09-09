# CLI Entrypoints (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Argument parsing, output-file writing, exit-code gating, and `.soc2rc.yml`
discovery for the two ways a human or CI pipeline invokes the engine:
`audit_repo.py` (native regex scanner) and `universal_audit.py` (external
OSS orchestrator). Neither file contains detection logic — see
[auditor-core](../auditor-core/SYSTEM.md).

Does not own: any finding-detection logic, report rendering internals (calls
into `auditor.reporting`).

## 2. Sub-System Decomposition

Atomic leaf (BUILD — trivial+stable CLI glue).

## 3. Interface Contracts

- **Inputs:** process command-line arguments per each file's own argument parser definitions; optional per-directory soc2rc config file.
- **Outputs:** process exit code (0 or 1 per `--fail-on`/gate logic); stdout (text or JSON); optionally written `--sarif`/`--markdown` files.

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL exit 1 when `--fail-on` names a severity
  and any finding at/above it exists, else exit 0 (`test_cli_fail_on_gate`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF `<directory>/.soc2rc.yml` exists and parses THEN THE
  SYSTEM SHALL merge its `exclude`/`min_severity`/`disable_rules` with CLI
  flags, CLI flags taking precedence for `min_severity` (R-014;
  `TestSoc2rcConfig`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a malformed `.soc2rc.yml` is present THEN THE SYSTEM
  SHALL warn to stderr and proceed as if it were absent, never crash
  (`test_malformed_config_does_not_crash`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a `--sarif`/`--markdown` output path resolves inside
  the directory being scanned THEN THE SYSTEM SHALL warn to stderr before
  writing (R-023; `TestOutputPathWarning`).
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-121:** `.soc2rc.yml` schema is intentionally minimal (`exclude`,
  `min_severity`, `disable_rules`) — matches what R-014's stated pain point
  actually needed, not a speculative superset.
- **ADR-122:** The output-path warning (R-023) is a warning, not a hard
  refusal — blocking would break pipelines that have a deliberate reason to
  write inside the scan target; the goal is visibility, not prevention.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/audit_repo.py`, `scripts/universal_audit.py`
- **Test Surface Seam:** `scripts/test_audit_repo.py`, `scripts/test_universal_audit.py` (run via `python -m pytest`; shared with auditor-core - these files are thin enough that splitting the test seam would fragment coverage of the same behaviors without adding signal)

## 7. Measurement Seams

- **Primary Metric:** `pytest_pass_rate` (target: 1.0; direction: higher)
- **Evaluation Gate:** `python -m pytest scripts/test_audit_repo.py
  scripts/test_universal_audit.py` (exit 0)
- **Correctness Backpressure:** manual CLI smoke test
  (`python scripts/audit_repo.py <dir> --json`) before each release.
- **Telemetry Surface:** none.
- **Branching Policy:** n/a — direct commits to `main`.

## 8. Technology Resolution

- **Decision class:** BUILD
- **Justification:** `argparse` over the stdlib is the obvious, zero-cost
  choice for two subcommand-free CLIs; no case for a CLI framework at this
  scale (2 entrypoints, ~15 flags total).
- **Selected:** Python stdlib `argparse` + PyYAML for `.soc2rc.yml`.
- **Standard / protocol:** none.
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | click / typer | adds a dependency for functionality argparse already provides at this scale |
- **Fit gap:** none known.
- **Seam:** `main(argv=None) -> int` in each file.
- **Exit cost:** LOW.
- **Cost model:** $0.
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** a CI pipeline that doesn't check the exit code silently
  ignores `--fail-on` - documented in README, not something the CLI itself
  can enforce.
- **Open questions:** none.
