# Framework Coverage Audit — 2026-09-02

**Trigger:** requested check of AuditForge's compliance-framework coverage against
what's available in the wild, after `docs/field-test-*` reports and ROADMAP
updates landed. Session also ran `scripts/update_sources.ps1` for the first
time in this workspace (only `config/`, `docs/`, `scripts/` existed beforehand
— every knowledge-base clone in CLAUDE.md's Workspace Layout table had to be
pulled fresh).

## 0. Pre-check: source registry hygiene

`scripts/update_sources.ps1`'s source list contained two entries with no
relationship to compliance frameworks and no mention in CLAUDE.md's Workspace
Layout table:

- `firefox` → `mozilla-firefox/firefox.git` (multi-GB browser source tree).
  User confirmed this is an intentional test-case target for the project and
  should stay.
- `Anthropic-Cybersecurity-Skills` → `mukul975/Anthropic-Cybersecurity-Skills.git`,
  an individual's personal repo, not an official Anthropic org repo, despite
  the name. User confirmed this is unneeded.

Removed `Anthropic-Cybersecurity-Skills` from `scripts/update_sources.ps1`,
`.gitignore`, and `docs/architecture/modules/workspace-hygiene/checks.ps1`.
`firefox` was restored/kept per user direction. The background clone job was
stopped before it reached either entry, so nothing was ever pulled.

## 1. What's actually wired into `framework_metadata.json` today

`scripts/sync_frameworks.py` (`SOURCES` dict + `sync_all()`) parses
per-control data for only **8 of its 11 registered families**:

| Family | Parsed? | Source |
| --- | --- | --- |
| NIST CSF v1.1 (legacy) | yes | `nist-csf/README.md` regex |
| JupiterOne policies | yes | `jupiterone-policies/templates/policies` |
| NIST SP 800-53 R5 | yes | OSCAL JSON catalog |
| NIST SP 800-171 R3 | yes | OSCAL JSON catalog |
| NIST CSF 2.0 | yes | OSCAL JSON catalog |
| HIPAA Security Rule | yes | `compliance-as-code/controls/hipaa.yml` |
| PCI DSS v4.0 | yes | `compliance-as-code/controls/pcidss_4.yml` |
| OWASP ASVS 5.0 | yes | `asvs/5.0/docs_en` |
| OWASP Top 10:2025 | **presence-only** | `_register_family`, no controls parsed |
| MITRE ATT&CK Enterprise | **presence-only** | `_register_family`, no controls parsed |
| SCF crosswalk | **presence-only** | `_register_family`, no controls parsed |

## 2. Gap A — CIS / Essential Eight / STIG are cloned but never read

CLAUDE.md's Workspace Layout table claims `compliance-as-code/` gives
"HIPAA / PCI-DSS 4.0.1 / CIS / E8 / STIG control YAML." Verified directly:

- `compliance-as-code/controls/e8.yml` exists (Essential Eight).
- `compliance-as-code/controls/stig_ocp4.yml`, `stig_ol9.yml`,
  `stig_ubuntu2204.yml`, `stig_ubuntu2404.yml`, `stig_slmicro5.yml` exist,
  plus hundreds of `*_stig` rule references under `linux_os/guide/`.
- `products/*/profiles/cis*.profile` exists per-distro (al2023, almalinux9,
  debian12, etc.).

None of these are in `sync_frameworks.py`'s `SOURCES`/`sync_all()` — only
`hipaa.yml` and `pcidss_4.yml` are read. CIS, E8, and STIG are physically
present on disk but contribute **zero controls** to `framework_metadata.json`.

## 3. Gap B — the SCF crosswalk is the widest source in the workspace, and it's unparsed

`secure-controls-framework/secure-controls-framework-scf-2026-2.xlsx`:

- **"Focal Documents" sheet**: 255 distinct mapped frameworks/regulations
  across General / US-Federal / US-State / EMEA / APAC / Americas geographies
  — including ISO/IEC 27001:2022, 27002:2022, 27017:2015, 27018:2025,
  27701:2025, 42001:2023, 22301:2019; GDPR (EU 2016); DORA (EU 2023); NIS2
  (EU 2022 + Annex 2024); EU AI Act; EU Cyber Resiliency Act; CMMC 2.0
  (L1/L2/L3); FedRAMP R5 (Low/Mod/High/LI-SaaS); TISAX 6.0.3; UK Cyber
  Essentials 3.3; UK CAF 4.0; Germany BSI C5; SOX; GLBA (CFR 314); NYDFS 23
  NYCRR 500; FERPA; COPPA; CJIS 6.0; FINRA; SEC Cybersecurity Rule; CSA CCM
  4.1.0; COBIT 2019; NIST AI RMF; Australia Essential Eight 2024 + CPS
  230/234; Brazil LGPD; Canada PIPEDA; and dozens more state/national privacy
  laws.
- **"SCF 2026.2" sheet**: 372 columns of per-SCF-control mappings against
  those same focal documents — i.e., an actual structured crosswalk, not just
  a name list.

`sync_frameworks.py` only checks that the `secure-controls-framework/`
directory exists (`_register_family`) and never opens the workbook. All 255
frameworks it maps are sitting in the clone, unparsed and unqueryable through
`framework_metadata.json`.

## 4. Gap C — real blind spots (absent even from the 255-document SCF crosswalk)

Cross-referenced against Drata's and Vanta's public framework lists (see
Sources). Three commonly-requested frameworks appear in neither the SCF
crosswalk nor anywhere else in this workspace:

- **HITRUST CSF** — frequent healthcare/SaaS vendor-questionnaire ask.
- **FFIEC (CAT)** — banking/fintech vendor ask.
- **SOC 1 / SSAE 18** — financial-reporting-controls attestation, commonly
  paired with SOC 2 in the same audit engagement.

No local knowledge base references any of the three by name.

## 5. Gap D — MITRE ATT&CK: only Enterprise is read (minor)

`attack-stix-data/` clones `enterprise-attack/`, `ics-attack/`, and
`mobile-attack/`; `sync_frameworks.py` only checks `enterprise-attack/`. Low
priority given this project's web/cloud/SDLC focus — ICS and mobile ATT&CK
matter far less here than for an OT- or mobile-focused shop.

## 6. Non-gaps (already strong)

NIST 800-53 R5, NIST 800-171 R3, NIST CSF 2.0, SSDF (via OSCAL), MITRE ATT&CK
Enterprise, HIPAA, PCI DSS 4.0, CIS/E8/STIG (data present, wiring is Gap A),
OWASP ASVS 5.0, OWASP Top 10:2025, and SOC 2 (native focus of `audit_repo.py`
+ comply/JupiterOne policy wording) — this is already a wider base than most
single-purpose OSS scanners carry, before even counting the SCF crosswalk.

## Sources

- [Understanding Security Frameworks (Secureframe)](https://secureframe.com/blog/security-frameworks)
- [Cybersecurity Frameworks Explained: A Complete List for 2026 (Fonzi)](https://fonzi.ai/blog/cybersecurity-frameworks)
- Framework-coverage lists cross-referenced from Drata and Vanta product pages
  (via web search, 2026-09-02) for the "what do commercial GRC platforms cover
  that we don't" comparison in §4.

## Proposed Backlog

See ROADMAP.md R-025 through R-028 (superseded numbering below).

## 7. Implementation — same session

All of R-025, R-026, and the MITRE ATT&CK/ASVS gaps from §1 were closed
same-session (ROADMAP.md R-025, R-026, R-031, R-032, R-033):

- `scripts/sync_frameworks.py::_parse_cac_controls_dir()` — auto-discovers
  every `compliance-as-code/controls/*.yml` (both the single-file and
  split-directory `controls/<id>/section-*.yml` layouts), instead of the two
  hand-picked HIPAA/PCI-DSS calls that existed before. **47 framework
  families** now parse: CIS (10 products), STIG (5 products), Essential
  Eight, BSI (Germany, 3 variants), ANSSI (France), CCN (Spain), ISM
  (Australia), DISA SRG (2 variants), HIPAA, PCI DSS 3/4, and 5 per-product
  NIST overlays (OCP4, RHACM, RHCOS4, RHIdM, Satellite6). 145 individual
  per-control section files were skipped (unquoted Jinja2 macros, e.g.
  `{{{ full_name }}}`, that aren't valid standalone YAML outside
  ComplianceAsCode's own build pipeline) — logged, not silently dropped.
- `scripts/sync_frameworks.py::_parse_scf_crosswalk()` — parses
  `secure-controls-framework-scf-2026-2.xlsx` via `openpyxl` (added to
  `requirements.txt`). Cross-references the "Focal Documents" sheet against
  the "SCF 2026.2" sheet's 372 mapping columns. **248 focal-document
  frameworks** registered (of 252 with a matched column), **30,577
  SCF-control-to-clause mappings** — verified live for ISO 27001:2022 (51
  controls, exact clause numbers) and spot-checked for GDPR, NYDFS 23 NYCRR
  500, CIS Controls v8, and 240+ others.
- `scripts/sync_frameworks.py::_parse_attack()` — MITRE ATT&CK Enterprise
  went from a presence-only flag to a real per-technique parse of the STIX
  2.1 bundle: **697 techniques** indexed by ATT&CK ID (e.g.
  `ATTACK:T1055.011` → "Extra Window Memory Injection").
- **Bug found and fixed while doing this**: `_parse_asvs()` was silently
  indexing **0** ASVS controls — OWASP ASVS 5.0.0's JSON export changed
  schema (top-level `Requirements` + `Description` on leaf nodes, not the
  `chapters`/`Name` shape the parser was written against) sometime after the
  parser was last touched. Fixed; now indexes 442 controls. The family showed
  as "found" in the sync log the whole time, which is exactly the kind of
  silent gap this audit was trying to surface.
- `requirements.txt`: added `openpyxl>=3.1` (crosswalk parsing) and
  `pytest>=8.0` (was an undeclared dependency of `test_build_rulepack.py`,
  caught by `docs/architecture/modules/workspace-hygiene/checks.ps1`).

**Result:** `framework_metadata.json` went from **11 families / 2,075
controls** to **303 families / 42,082 controls** (3.3 MB, regenerates in
~7s). `python scripts/audit_repo.py scripts` and the workspace-hygiene check
both pass clean on the changed code.

**Still open:** R-027 (HITRUST CSF, FFIEC CAT, SOC 1/SSAE 18 — no local
source contains any of the three, would need a new external KB) and R-030
(MITRE ATT&CK ICS/Mobile subtrees, low priority for this project's
web/cloud/SDLC focus).
