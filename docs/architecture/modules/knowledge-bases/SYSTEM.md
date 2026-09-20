# Knowledge Bases (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Provide local, authoritative, machine-readable control catalogs for every major
IT/cybersecurity framework the mappings reference, at zero cost.

Does not own: parsing them into metadata (session-updater owns regeneration),
scanning code, or policy authoring.

## 2. Sub-System Decomposition

Atomic leaf (procured — all sources are ADOPT clones/downloads).

## 3. Interface Contracts

- **Inputs:** recorded origin git URLs and download URLs for each framework
  family (this module owns that registry).
- **Outputs:** read-only directories at workspace root:
  `oscal-content/`, `attack-stix-data/`, `asvs/`, `owasp-top10/`,
  `compliance-as-code/`, `secure-controls-framework/`, plus existing
  `nist-csf/`, `gdpr-checklist/`, `security-templates/`, `jupiterone-policies/`,
  `comply/`, and `references/` for single-file downloads.

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** EVERY knowledge base directory SHALL be a git clone of its
  recorded origin (or a downloaded public-domain file under `references/`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a source's license forbids redistribution THEN THE
  SYSTEM SHALL record it as DEFER in ROADMAP.md instead of vendoring it.
  - `EvidenceStage:` Observed
- **[Ubiquitous]** THE SYSTEM SHALL NOT contain any paid-API-dependent source.
  - `EvidenceStage:` Observed

## 5. Architectural Decisions (ADRs)

- **ADR-101:** Shallow clones (`--depth 1`) for large repos (oscal-content ~90MB,
  attack-stix-data ~126MB, ComplianceAsCode ~125MB) — history is irrelevant;
  freshness comes from `git pull --ff-only`. Exit cost LOW (delete + reclone).
- **ADR-102:** PCI-DSS text via ComplianceAsCode `pcidss_4.yml` is internal-use
  only (SSC-authored text embedded in a BSD repo); never republished.
- **ADR-103:** CSA CCM excluded: free internal use but commercial embedding needs
  $15k–30k/yr license; cloud coverage arrives via SCF + 800-53 instead.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** origin registry (source table inside the updater
  script), `references/`
- **Test Surface Seam:** `docs/architecture/modules/knowledge-bases/checks.ps1`

## 7. Measurement Seams

- **Primary Metric:** `framework_catalogs_present` (target: >= 12 distinct
  framework families resolvable locally; direction: higher)
- **Evaluation Gate:** `docs/architecture/modules/knowledge-bases/measure.ps1`
- **Correctness Backpressure:** `docs/architecture/modules/knowledge-bases/checks.ps1`
- **Telemetry Surface:** updater summary table lines per source.
- **Branching Policy:** n/a — data acquisition module; changes land via updater runs.

## 8. Technology Resolution

- **Decision class:** ADOPT
- **Justification:** n/a (not BUILD)
- **Dependency:** oscal-content
- **Pin:** 78650f02ad9321bb7b817846f8fbd4f2bcd620de
- **Reference kind:** commit
- **Selected:**
  | Family | Source | Format |
  | --- | --- | --- |
  | NIST 800-53 R5 / 800-171 R3 / CSF 2.0 / SSDF / 800-172 | github.com/usnistgov/oscal-content | OSCAL JSON |
  | MITRE ATT&CK v9 | github.com/mitre-attack/attack-stix-data | STIX 2.1 JSON |
  | OWASP ASVS 5.0 | github.com/OWASP/ASVS | JSON/CSV/XML |
  | OWASP Top 10:2025 | github.com/OWASP/Top10 | OSIB YAML |
  | HIPAA / PCI-DSS 4.0.1 / CIS / E8 / STIG controls | github.com/ComplianceAsCode/content | YAML |
  | SCF crosswalk (~120 frameworks incl. ISO 27001:2022, CCM, CIS columns) | github.com/securecontrolsframework/securecontrolsframework | XLSX (CC BY-ND) |
  | GDPR checklist / legacy NIST CSF v1.1 / J1 policies / Comply | existing clones | MD/YAML |
- **Standard / protocol:** OSCAL, STIX 2.1
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | CSA CCM v4 machine-readable bundle | commercial embedding license $15k+/yr |
  | CIS Controls master Excel | registration-gated form; no-redistribution terms |
  | ISO/IEC 27001:2022 text | CHF 155, copyright prohibits reproduction |
  | GSA/fedramp-automation | repo deleted (404); baselines duplicate 800-53 Rev5 |
  | PCI SSC document library | account-gated, PDF-only, no redistribution |
- **Fit gap:** no live vendor risk feed; OSV scanner already covers vulnerability
  currency separately.
- **Seam:** directory presence + git origin URL per family.
- **Exit cost:** LOW (delete dir, edit table row).
- **Cost model:** $0 all sources; would change if a family requires SecureSuite.
- **Liability transferred:** upstream authors own content correctness.
- **Operational owner:** us (git pulls).
- **Failure mode:** upstream deletes/moves a repo (precedent: fedramp-automation);
  fallback = pin a community mirror, log in updater table.
- **Open questions:** none
