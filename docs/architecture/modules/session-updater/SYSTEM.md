# Session Updater (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

One command, run at the start of any working session, that brings every knowledge
base to latest, regenerates derived metadata, inventories audit tools, and reports
per-source status.

Does not own: clone URL truth (knowledge-bases owns it), scanner execution logic,
or report generation.

## 2. Sub-System Decomposition

Atomic leaf (build — small integration glue).

## 3. Interface Contracts

- **Inputs:** invocation as pwsh scripts/update_sources.ps1 with optional SkipSync flag; consumes knowledge-bases origin registry.
- **Outputs:** exit code 0 on success / non-zero on any pull-or-clone failure; stdout summary table (Repo | LastCommit | Status); regenerated `scripts/framework_metadata.json`; maintained `scripts/update_sources.ps1`.

## 4. Invariants (EARS + Epistemic Stage)

- **[Event-driven]** WHEN invoked THE SYSTEM SHALL pull every existing knowledge-
  base clone with `git pull --ff-only` and never create merge commits.
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a registered source directory is missing THEN THE SYSTEM
  SHALL shallow-clone it from its recorded origin.
  - `EvidenceStage:` Unknown
- **[Ubiquitous]** THE SYSTEM SHALL finish by running `sync_frameworks.py` unless
  `-SkipSync` was passed.
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL report which of checkov/semgrep/trivy/
  osv-scanner are installed, with versions where available.
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-201:** Consolidate the old split (update_sources.ps1 pulls,
  sync_frameworks.py fetched separately) into one entrypoint; sync_frameworks.py
  remains the parser but is no longer a separate session step.
- **ADR-202:** PowerShell not Python for orchestration: git invocation and Windows
  console table output are native here; python is invoked once for parsing.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/update_sources.ps1`
- **Test Surface Seam:** `docs/architecture/modules/session-updater/checks.ps1`

## 7. Measurement Seams

- **Primary Metric:** `updater_success_all_sources` (target: 1.0 = all rows non-
  FAILED; direction: higher)
- **Evaluation Gate:** `docs/architecture/modules/session-updater/measure.ps1`
- **Correctness Backpressure:** `docs/architecture/modules/session-updater/checks.ps1`
- **Telemetry Surface:** per-source status rows + tool inventory lines.
- **Branching Policy:** n/a — single-file script; direct commits acceptable.

## 8. Technology Resolution

- **Decision class:** BUILD
- **Justification:** trivial and stable — ~60 lines of git plumbing around local
  repos; no library or service performs "pull my heterogeneous local clones plus
  regenerate my project-specific metadata".
- **Selected:** PowerShell 5.1 script + existing Python parser (`sync_frameworks.py`)
- **Standard / protocol:** none (local process invocation)
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | git submodules / meta tools (mu-repo, gita) | extra dependency for what is one loop; submodule pinning fights always-latest goal |
  | Makefile/just | not native to this Windows-first workspace |
- **Fit gap:** does not auto-update scanner binaries themselves (trivy DB etc.);
  tool inventory only reports presence.
- **Seam:** `scripts/update_sources.ps1` exit code + summary rows.
- **Exit cost:** LOW (single file replaceable).
- **Cost model:** $0; irrelevant at any scale.
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** offline → pulls fail, script reports FAILED rows and exits
  non-zero; stale caches remain usable.
- **Open questions:** none
