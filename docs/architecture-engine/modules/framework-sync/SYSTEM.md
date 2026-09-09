# Framework Sync (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Derives two files from the read-only knowledge-base clones (owned by
`docs/architecture/SYSTEM.md`'s tree): `scripts/framework_metadata.json`
(the flat control index, `sync_frameworks.py`) and
`scripts/document_catalog.db` (the standards-themselves catalog with
license classification and optional cached full text,
`build_document_catalog.py`). Also `build_rulepack.py`, which emits a
separate host-posture rule pack for the sibling RoninAI project, sharing
only a control-tagging convention with the other two.

Does not own: which knowledge bases are cloned or kept fresh (that's
`docs/architecture/modules/session-updater/SYSTEM.md`, which invokes
`sync_frameworks.py` as its own last step — this node owns the *parsing*
logic inside that file, not the invocation).

## 2. Sub-System Decomposition

Atomic leaf (BUILD — pre-existing, field-tested; grew from 11 to 306
framework families and 1 to 155/167 cached documents across this and prior
sessions, per ROADMAP's Completed table).

## 3. Interface Contracts

- **Inputs:** the knowledge-base clones at the workspace root (`oscal-content/`, `compliance-as-code/`, `attack-stix-data/`, `secure-controls-framework/`, `fedramp-rules/`, `asvs/`, `owasp-top10/`).
- **Outputs:** `scripts/framework_metadata.json` (`{"frameworks": {...}, "controls": {...}}`), `scripts/document_catalog.db` (SQLite, `documents` table), optionally cached document bodies under `scripts/document_cache/` (gitignored).

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL be fully regenerable from the clones —
  never accept hand-edits to `scripts/framework_metadata.json` or
  `scripts/document_catalog.db` (CLAUDE.md Workspace Layout mandate).
  - `EvidenceStage:` Observed
- **[Ubiquitous]** THE SYSTEM SHALL classify every cataloged document's
  redistribution rights, defaulting to the most restrictive
  (`unknown`) when unverified (`TestClassification`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a document is not classified `public_domain` or
  `free_to_access` THEN THE SYSTEM SHALL refuse to fetch it, with zero
  network calls (`test_refuses_copyrighted_without_network_call`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a fetched response is empty, matches a known
  access-wall title signal, or contains a bot-challenge script THEN THE
  SYSTEM SHALL refuse to mark it cached (R-041; `TestLooksBlocked`).
  - `EvidenceStage:` Sampled

## 5. Architectural Decisions (ADRs)

- **ADR-131:** Two independent derived artifacts, not one — `controls`
  (`scripts/framework_metadata.json`) and `documents` (`scripts/document_catalog.db`)
  answer different questions ("what does control X say" vs. "where do I get
  the real standard Y") and have different regeneration triggers.
- **ADR-132:** `build_document_catalog.py`'s license classification is a
  conservative heuristic keyed off the SCF crosswalk's `Source` column, not
  a legal opinion — "unknown" is the safe default (see `SOURCE_LICENSE`).
- **ADR-133 (R-041):** Landing-page/access-wall detection
  (`_looks_blocked`) is a small, evidence-backed denylist (empty response,
  specific title phrases, known bot-challenge markers) derived from
  manually verifying all 21 flagged documents in one session, not a general
  content classifier — extending it should be evidence-driven the same way.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/sync_frameworks.py`,
  `scripts/build_document_catalog.py`, `scripts/build_rulepack.py`,
  `scripts/test_sync_frameworks.py`, `scripts/test_document_catalog.py`,
  `scripts/test_build_rulepack.py` (test files listed here too - see
  auditor-core's note on why Test Surface Seam alone isn't sufficient)
- **Test Surface Seam:** `scripts/test_sync_frameworks.py`, `scripts/test_document_catalog.py`, `scripts/test_build_rulepack.py` (run via `python -m pytest`)

## 7. Measurement Seams

- **Primary Metric:** `pytest_pass_rate` (target: 1.0; direction: higher);
  secondarily, `document_cache_coverage` (155/167 eligible as of
  2026-09-09 - tracked in ROADMAP, not a hard gate).
- **Evaluation Gate:** `python -m pytest scripts/test_sync_frameworks.py
  scripts/test_document_catalog.py scripts/test_build_rulepack.py` (exit 0)
- **Correctness Backpressure:** `python scripts/sync_frameworks.py`'s own
  per-source `[+]`/`[!]` presence log + printed control/family counts,
  eyeballed against the prior run's counts for unexpected drops.
- **Telemetry Surface:** none.
- **Branching Policy:** n/a — direct commits to `main`.

## 8. Technology Resolution

- **Decision class:** BUILD
- **Justification:** parsing ~15 heterogeneous source formats (OSCAL JSON,
  STIX 2.1, YAML, XLSX) into one flat index is inherently project-specific;
  no library does "parse AuditForge's specific mix of knowledge bases."
- **Selected:** Python stdlib (`json`, `re`) + PyYAML + openpyxl (XLSX) +
  requests (document fetching).
- **Standard / protocol:** OSCAL (NIST), STIX 2.1 (MITRE) as input formats
  only - not re-emitted.
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | A general OSCAL toolchain (e.g. `oscal-cli`) | still wouldn't parse the non-OSCAL sources (STIX, SCF xlsx, ComplianceAsCode YAML) - would need custom code anyway for most of the actual sources |
- **Fit gap:** OWASP Top 10:2025's OSIB export stays presence-only (deeply
  nested CWE-linkage graph, not a flat control list) - documented as
  deliberate in `sync_frameworks.py`'s own comments, not a silent gap.
- **Seam:** `FrameworkManager.sync_all()` / `build_document_catalog.build()`.
- **Exit cost:** MEDIUM — parser logic is source-format-specific and would
  need rewriting per format if replaced.
- **Cost model:** $0 (local clones + occasional document fetches).
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** a knowledge-base clone with a changed export schema
  silently parses to 0 controls for that family unless the family's control
  count is checked against the prior run (this exact failure mode is how
  R-032's ASVS 0-control bug was found).
- **Open questions:** none.
