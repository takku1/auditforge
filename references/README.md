# references/ - user-supplied framework drop-ins

`scripts/sync_frameworks.py` parses files placed in these directories during
its normal run. Nothing here is ever fetched automatically: AuditForge only
auto-clones public-domain / freely-redistributable sources. Directories
marked GATED contain frameworks whose licenses forbid automated fetching
(registration walls, Fair-Use-only terms, or subscription agreements) - for
those, download the file yourself under that publisher's terms and drop it
here; the parser activates only when the file is present.

Layout: one subdirectory per framework, flat files inside (no nesting).

## Open sources (safe to download; still manual until a clone layout is wired)

| Directory | Expected file | Where to get it |
| --- | --- | --- |
| `samm/` | `*.yaml` / `*.yml` - SAMM v2 datamodel, indexed per `type` tag: Activity (`title` + `shortDescription`), Practice (`name` + `shortDescription`), PracticeLevel (`objective`), Function/Stream (`name` + `description`), Question (`text` + `quality`), MaturityLevel (`number` + `description`); AnswerSet files skipped, unknown shapes fall back to recursive name+description indexing | owaspsamm.org or github.com/OWASP/samm (CC BY-SA 4.0) |
| `nist-800-63-4/` | `sp800-63{,a,b,c}.html` volumes - each `<h2>/<h3 id="slug">` + first `<p>` becomes one `NIST80063:<VOL>-<SLUG>` entry (upstream ships HTML, not section markdown; `*.md` with numbered headers is still parsed when present) | github.com/usnistgov/800-63-4, official PDFs via doi.org/10.6028/NIST.SP.800-63-4 (public domain) |
| `cvss-v4/` | `*.json` as `{"metrics": [{"id": "AV", "name": "Attack Vector", "description": "..."}]}` or a bare `[...]` list; raw upstream `cvss_config.js` (`"Name (SHORT)": {"tooltip", "short"}`) is parsed directly | github.com/FIRSTdotorg/cvss-v4-calculator (BSD-2-Clause; metric code/schema only, not spec prose) |
| `bsimm/` | `*.md` with practice headers, e.g. `## Strategy & Metrics (SM)` + a lead paragraph | bsimm.com (CC BY-SA; confirm current download terms first) |
| `cisa-cpg/` | `*.csv` / `*.tsv` with a header row; ID column (`id`, `goal id`, ...) + title column (`goal`, `title`, ...) and optional `description` (current `cpg-2.0.csv`: 34 goals derived from the official cisa.gov listing; prefer an official xlsx/worksheet if CISA publishes one) | cisa.gov Cross-Sector Cybersecurity Performance Goals 2.0 (public domain) |
| `cwe/` | `cwec_v*.xml` (or the `cwec_latest.xml.zip` that ships it) - `<Weakness ID Name>` + `<Description>` becomes one `CWE:CWE-<id>` entry; element names match namespace-tolerantly so schema revisions keep parsing | cwe.mitre.org/data/xml/cwec_latest.xml.zip (MITRE free download, no registration; refreshed by update_sources.ps1 `$directDownloads`) |
| `capec/` | `capec_latest.xml` (or a `views/*.xml` / `*.zip` export) - `<Attack_Pattern ID Name>` + `<Description>` becomes one `CAPEC:CAPEC-<id>` entry | capec.mitre.org/data/xml/capec_latest.xml (MITRE free download, no registration; refreshed by update_sources.ps1 `$directDownloads`) |
| `nist-ai-rmf/` | `NIST.AI.100-1.pdf` - GOVERN/MAP/MEASURE/MANAGE `major.minor` subcategories become `AIRMF:<FUNC>-<major>.<minor>` entries (PDF line-wrap hyphens rejoin) | nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf (public domain; refreshed by update_sources.ps1 `$directDownloads`) |
| `nist-ai-600-1/` | `NIST.AI.600-1.pdf` - MS-/MG- action IDs (line-opening ID + same-line title) become `GENAI:<ID>` entries | nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf (public domain; manual drop-in) |
| `c2m2/` | `C2M2-Version-2.1.pdf` - `6.N` domain headings + `N. Title` objectives + `MIL1/2/3 <letter>.` practices become `C2M2:<DOMAIN>-<objective><letter>` entries (e.g. `C2M2:ASSET-1A`); TOC leaders/page headers never open headings | energy.gov C2M2 v2.1 model PDF (public domain; refreshed by update_sources.ps1 `$directDownloads`) |
| `ffiec/` | `FFIEC_ITBooklet_InformationSecurity-2016.pdf` - dotted subsections (`II.C.19`) + Appendix A `Objective N:` lines become `FFIEC:IS-*` entries (exam objectives keep directive title + procedure prose); TOC leaders, page numbers, and pypdf-merged running headers/footers are stripped | ithandbook.ffiec.gov InfoSec booklet Sept 2016 (public domain; ffiec.gov WAF-blocks automation, so seeded via Wayback capture of the official PDF - refresh via update_sources.ps1 `$directDownloads` Wayback URL or manual re-drop) |
| `disa-stig/` | quarterly `*.zip` (each holding a `*-Manual-xccdf.xml`) or loose `*.xml` - each `<Group id="V-...">` + `<Rule>` description becomes one `STIG:<BENCH>:<V-ID>` entry (V-IDs repeat across STIGs, hence the benchmark namespace); namespace-tolerant for XCCDF 1.1/1.2 | public.cyber.mil/stigs/downloads/ (public domain, free, no registration; versioned quarterly with no `latest` URL, so manual drop-in - never script a fetch) |

## GATED sources (manual download only - never script a fetch)

| Directory | Expected file | Terms |
| --- | --- | --- |
| `cis-controls/` | `*.csv` - CIS Controls v8.1 safeguards (header row; safeguard ID + title columns) | cisecurity.org - master Excel is registration-gated, no redistribution (ROADMAP RF-001) |
| `ccm-bundle/` | `ccm-v4.1.0-minimal.json` - IDs + short titles only (207 controls; no `specification` prose per CSA fair-use terms); full archive (`*.zip`, `extracted/`) stays gitignored and uncommitted; nested `domains[].controls[]` with `description`/`specification` also parses if ever dropped in | cloudsecurityalliance.org no-account bundle link - Fair-Use-only; internal use, never commit or redistribute (ROADMAP RF-002) |
| `hitrust-csf/` | `*.csv` - HITRUST CSF control statements (header row; ID + title columns) | hitrustalliance.net - MyCSF subscription agreement required (ROADMAP R-027) |
| `csa-caiq/` | `*.csv` - CAIQ v4 questions (header row) | CSA - form-gated, personal/noncommercial/no-modify license |
| `csa-aicm/` | `*.csv` - AICM controls (header row) | CSA - form-gated, personal/noncommercial-only license |

Fixture files in `scripts/` tests are synthetic (invented IDs/titles), never
real gated text. Keep it that way: do not commit real CIS/CCM/HITRUST/CAIQ/
AICM content to this repo.
