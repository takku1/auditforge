# AuditForge (L0)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

AuditForge keeps a local, always-fresh, 100%-free library of IT/cybersecurity
compliance frameworks and turns it into multi-framework audit evidence for any
codebase.

Does not own: the audit engine's detection logic (pre-existing, out of scope for
this tree), upstream framework authoring, or network DAST target selection.

## 2. Sub-System Decomposition

Non-terminal; child links below.

- [knowledge-bases](modules/knowledge-bases/SYSTEM.md) — free authoritative
  framework catalogs, cloned/downloaded locally.
- [session-updater](modules/session-updater/SYSTEM.md) — one command that pulls
  every knowledge base to latest and regenerates derived metadata.
- [workspace-hygiene](modules/workspace-hygiene/SYSTEM.md) — version control,
  layout, and dependency hygiene for project-owned files.

## 3. Interface Contracts

- **Inputs:** a working directory containing `config/compliance_config.yaml`,
  `scripts/`, and cloned knowledge-base directories at the workspace root.
- **Outputs:** refreshed clones, `scripts/framework_metadata.json` (multi-
  framework control index), updater status table.

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL rely only on sources that are free of charge
  with no paid API keys.
  - `EvidenceStage:` Observed
- **[Conditional]** IF a knowledge base directory is missing THEN THE SYSTEM
  SHALL clone it from its recorded origin instead of failing.
  - `EvidenceStage:` Unknown
- **[Event-driven]** WHEN the session updater runs THE SYSTEM SHALL report per-
  source freshness (updated / up-to-date / failed) in one summary table.
  - `EvidenceStage:` Unknown

## 5. Architectural Decisions (ADRs)

- **ADR-001:** Knowledge bases are vendored read-only clones, never submodules —
  root repo gitignores them so `git pull --ff-only` inside each clone stays the
  update path. Impact: self-healing requires clone URLs registered in the updater.
- **ADR-002:** Framework coverage is consolidated through crosswalks (SCF xlsx as
  reference; NIST↔ISO mapping docx) rather than cloning copyrighted standards
  (ISO text paid; CIS master Excel registration-gated; CCM commercial-licensed).
  Those three are DEFER entries in ROADMAP.md.
- **ADR-003:** Derived control metadata is regenerated from source catalogs by a
  deterministic parser (`sync_frameworks.py`), never hand-edited.

## Child index

| Child | Class | Terminal |
| --- | --- | --- |
| modules/knowledge-bases | ADOPT | yes |
| modules/session-updater | BUILD (trivial+stable glue) | yes |
| modules/workspace-hygiene | BUILD (trivial+stable) | yes |
