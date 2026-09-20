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
