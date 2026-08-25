# Workspace Hygiene (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Keep project-owned files versioned, organized, and reproducible: git for owned
code, generated artifacts quarantined, declared Python dependencies pinned.

Does not own: knowledge-base clones (knowledge-bases), audit logic.

## 2. Sub-System Decomposition

Atomic leaf (build — trivial and stable).

## 3. Interface Contracts

- **Inputs:** workspace root layout conventions.
- **Outputs:** root `.git` repo; `.gitignore` covering clones, reports, caches,
  secrets; `requirements.txt`; `reports/` directory holding all generated audit
  artifacts; updated docs (CLAUDE.md/GEMINI.md) pointing at the new layout.

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE ROOT REPO SHALL track only project-owned files
  (`scripts/`, `config/`, `docs/`, agent MDs) and SHALL ignore every nested clone,
  `reports/`, `__pycache__/`, `.env`, and tool output dirs.
  - `EvidenceStage:` Observed
- **[Conditional]** IF a generated report exists at the workspace root THEN THE
  SYSTEM SHALL move it under `reports/`.
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** EVERY third-party import in `scripts/` SHALL appear in
  `requirements.txt`.
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-301:** Nested clones are gitignored rather than submodules: submodules pin
  commits, which contradicts the always-latest session goal and complicates
  `--depth 1` pulls.
- **ADR-302:** Single canonical reports directory (`reports/`) replaces the old
  root-level scatter and the unused `audit_reports` config value.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `.gitignore`, `requirements.txt`, `reports/`, doc updates
- **Test Surface Seam:** `docs/architecture/modules/workspace-hygiene/checks.ps1`

## 7. Measurement Seams

- **Primary Metric:** `root_stray_artifacts` (target: 0 files outside known-good
  set; direction: lower)
- **Evaluation Gate:** `docs/architecture/modules/workspace-hygiene/measure.ps1`
- **Correctness Backpressure:** `docs/architecture/modules/workspace-hygiene/checks.ps1`
- **Telemetry Surface:** git status porcelain output.
- **Branching Policy:** n/a — layout commit.

## 8. Technology Resolution

- **Decision class:** BUILD
- **Justification:** trivial and stable — file moves plus one .gitignore.
- **Selected:** plain git + pip requirements file.
- **Standard / protocol:** none.
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | poetry/uv project | no packaging need; stdlib+3 deps |
  | monorepo-ing the clones | license/redistribution risk, massive history bloat |
- **Fit gap:** no CI yet (out of scope this tree).
- **Seam:** `git status --porcelain` clean-ness on tracked paths.
- **Exit cost:** LOW.
- **Cost model:** $0.
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** developer drops stray file at root → measure flags it.
- **Open questions:** none
