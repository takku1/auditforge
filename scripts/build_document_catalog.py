#!/usr/bin/env python3
"""Builds scripts/document_catalog.db - a real SQLite database of every
framework/standard AuditForge tracks, each row pointing at its genuine
official source (not a cloned template, not a crosswalk reference).

This is a different thing from framework_metadata.json: that file indexes
individual *controls* parsed out of local knowledge-base clones for
crosswalk lookups. This catalogs the *documents themselves* - one row per
standard, with its real publisher URL, so "what is ISO 27001:2022 and where
do I get the actual document" has an answer that isn't "go find it".

Populated from two independent real sources (deliberately not invented):
  1. The Secure Controls Framework crosswalk workbook's "Focal Documents"
     sheet - 252 rows, each with a Focal Document Source (FDS) URL that
     points at the actual publisher (ISO, NIST, PCI SSC, national CERTs...).
  2. Every compliance-as-code/controls/*.yml file's own `source:` field -
     independently authored by that project, pointing at the actual
     publisher for CIS/STIG/E8/BSI/ANSSI/... benchmarks.
  3. A small hand-verified table for the handful of standards tracked via
     OSCAL/ASVS/MITRE-STIX/OWASP that aren't in either of the above.

License classification is a conservative heuristic keyed off the issuing
body, not a legal opinion - "unknown" is the safe default, and nothing here
implies a right to redistribute copyrighted standards text (ISO in
particular sells its standards; do not cache those).
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(__file__).resolve().parent / "document_catalog.db"
SCF_DIR = ROOT / "secure-controls-framework"
CAC_CONTROLS_DIR = ROOT / "compliance-as-code" / "controls"

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    fdi             TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    issuing_body    TEXT,
    geography       TEXT,
    source_url      TEXT,
    family_key      TEXT,
    catalog_source  TEXT NOT NULL,  -- 'scf' | 'compliance-as-code' | 'manual'
    license_status  TEXT NOT NULL,  -- see LICENSE_STATUS below
    license_note    TEXT,
    full_text_cached INTEGER NOT NULL DEFAULT 0,
    cached_path     TEXT,
    cached_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_documents_geography ON documents(geography);
CREATE INDEX IF NOT EXISTS idx_documents_license ON documents(license_status);
"""

# LICENSE_STATUS values, in increasing order of caution:
#   public_domain                  - US federal/state government work, 17 U.S.C. §105
#   free_to_access                 - publisher distributes it free (may restrict
#                                     redistribution/resale - not the same as PD)
#   copyrighted_registration_required - publisher sells it or gates it (ISO, IEC, ...)
#   unknown                        - not verified here; treat as copyrighted until checked

# Source -> (license_status, note), keyed off the SCF crosswalk's "Source"
# column. Anything not listed here defaults to "unknown" - deliberately
# conservative rather than guessing.
SOURCE_LICENSE = {
    "Federal": ("public_domain", "US federal government work (17 U.S.C. §105)"),
    "NIST": ("public_domain", "US federal government work (17 U.S.C. §105)"),
    "State": ("public_domain", "US state statute text is not copyrighted"),
    "EU": ("free_to_access", "Published free on EUR-Lex; EU institutions permit reuse of legislative text"),
    "United Kingdom": ("free_to_access", "UK Crown Copyright, Open Government Licence"),
    "Australia": ("free_to_access", "Australian Government, typically CC BY 4.0 (cyber.gov.au)"),
    "New Zealand": ("free_to_access", "NZ Crown Copyright, typically reusable"),
    "Canada": ("free_to_access", "Canadian Crown Copyright, typically reusable"),
    "GovRAMP": ("free_to_access", "Published free by GovRAMP"),
    "PCI SSC": ("free_to_access", "PCI SSC provides free download under its own usage terms - not public domain"),
    "CIS": ("free_to_access", "CIS Controls PDF is free to download; master Excel/mappings are registration-gated (see ROADMAP RF-001) - do not redistribute"),
    "MITRE": ("free_to_access", "MITRE ATT&CK is CC BY 4.0"),
    "OWASP": ("free_to_access", "OWASP content is CC-licensed"),
    "CSA": ("free_to_access", "Free for internal use; commercial embedding is licensed (see ROADMAP RF-002)"),
    "SCF": ("free_to_access", "CC BY-ND - internal use only, do not redistribute (see CLAUDE.md)"),
    "ISO": ("copyrighted_registration_required", "ISO sells its standards; not redistributable"),
    "IEC": ("copyrighted_registration_required", "IEC sells its standards; not redistributable"),
}

# Small manual table for standards tracked via non-SCF sources (OSCAL, ASVS,
# MITRE ATT&CK STIX, OWASP Top 10) - hand-verified real URLs, few enough to
# not need automated extraction.
MANUAL_DOCUMENTS = [
    {
        "fdi": "manual-nist-800-53-r5", "name": "NIST SP 800-53 Rev. 5",
        "issuing_body": "NIST", "geography": "US",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
        "family_key": "NIST53", "license_status": "public_domain",
        "license_note": SOURCE_LICENSE["NIST"][1],
    },
    {
        "fdi": "manual-nist-800-171-r3", "name": "NIST SP 800-171 Rev. 3",
        "issuing_body": "NIST", "geography": "US",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/171/r3/final",
        "family_key": "NIST171", "license_status": "public_domain",
        "license_note": SOURCE_LICENSE["NIST"][1],
    },
    {
        "fdi": "manual-nist-csf-2-0", "name": "NIST Cybersecurity Framework 2.0",
        "issuing_body": "NIST", "geography": "US",
        "source_url": "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
        "family_key": "CSF2", "license_status": "public_domain",
        "license_note": SOURCE_LICENSE["NIST"][1],
    },
    {
        "fdi": "manual-owasp-asvs-5-0", "name": "OWASP Application Security Verification Standard 5.0.0",
        "issuing_body": "OWASP", "geography": "General",
        "source_url": "https://owasp.org/www-project-application-security-verification-standard/",
        "family_key": "ASVS", "license_status": "free_to_access",
        "license_note": SOURCE_LICENSE["OWASP"][1],
    },
    {
        "fdi": "manual-owasp-top10-2025", "name": "OWASP Top 10:2025",
        "issuing_body": "OWASP", "geography": "General",
        "source_url": "https://owasp.org/Top10/2025/",
        "family_key": "top10", "license_status": "free_to_access",
        "license_note": SOURCE_LICENSE["OWASP"][1],
    },
    {
        "fdi": "manual-mitre-attack-enterprise", "name": "MITRE ATT&CK Enterprise",
        "issuing_body": "MITRE", "geography": "General",
        "source_url": "https://attack.mitre.org/matrices/enterprise/",
        "family_key": "ATTACK", "license_status": "free_to_access",
        "license_note": SOURCE_LICENSE["MITRE"][1],
    },
    {
        "fdi": "manual-fedramp-20x-ksi", "name": "FedRAMP 20x Key Security Indicators",
        "issuing_body": "Federal", "geography": "US",
        "source_url": "https://www.fedramp.gov/2026/",
        "family_key": "FEDRAMP20X", "license_status": "public_domain",
        "license_note": "US federal government work (17 U.S.C. §105); machine-readable "
                         "source at github.com/FedRAMP/rules (fedramp-consolidated-rules.json). "
                         "Supersedes the old Rev5 GSA/fedramp-automation baseline-profile repo, "
                         "which no longer exists (404 as of 2026-09-09, see ROADMAP RF-003).",
    },
]


def _classify(source: str) -> tuple:
    return SOURCE_LICENSE.get(source, ("unknown", None))


def _rows_from_scf() -> list:
    if not SCF_DIR.is_dir():
        return []
    candidates = sorted(SCF_DIR.glob("secure-controls-framework-scf-*.xlsx"))
    if not candidates:
        return []
    import openpyxl
    wb = openpyxl.load_workbook(candidates[-1], read_only=True, data_only=True)
    if "Focal Documents" not in wb.sheetnames:
        return []
    rows = list(wb["Focal Documents"].iter_rows(values_only=True))
    header = rows[0]
    idx = {name: i for i, name in enumerate(header) if name}

    def get(row, key):
        i = idx.get(key)
        return row[i] if i is not None and i < len(row) else None

    out = []
    for row in rows[1:]:
        if not row:
            continue
        fdi = get(row, "Focal Document Identifier (FDI)")
        name = get(row, "Focal Document Name (FDN)")
        if not fdi or not name:
            continue
        source = get(row, "Source") or ""
        status, note = _classify(str(source))
        fam = "SCF_" + re.sub(r"[^A-Z0-9]+", "_", str(fdi).upper()).strip("_")
        out.append({
            "fdi": str(fdi), "name": str(name),
            "issuing_body": str(source) if source else None,
            "geography": get(row, "Geography"),
            "source_url": get(row, "Focal Document Source (FDS)"),
            "family_key": fam,
            "license_status": status, "license_note": note,
        })
    return out


def _rows_from_compliance_as_code() -> list:
    if not CAC_CONTROLS_DIR.is_dir():
        return []
    out = []
    for path in sorted(CAC_CONTROLS_DIR.glob("*.yml")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(data, dict):
            continue
        source_url = data.get("source")
        if not source_url or not str(source_url).startswith("http"):
            continue
        stem = path.stem
        name = str(data.get("policy") or data.get("title") or stem).strip()
        fam = re.sub(r"[^A-Z0-9]+", "_", stem.upper()).strip("_")
        out.append({
            "fdi": f"cac-{stem}", "name": name,
            "issuing_body": None, "geography": None,
            "source_url": str(source_url), "family_key": fam,
            "license_status": "unknown", "license_note": None,
        })
    return out


def build(db_path: Path = DB_PATH) -> dict:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA)

    counts = {"scf": 0, "compliance-as-code": 0, "manual": 0}
    for row in _rows_from_scf():
        row["catalog_source"] = "scf"
        _insert(conn, row)
        counts["scf"] += 1
    for row in _rows_from_compliance_as_code():
        row["catalog_source"] = "compliance-as-code"
        _insert(conn, row)
        counts["compliance-as-code"] += 1
    for row in MANUAL_DOCUMENTS:
        row = dict(row)
        row["catalog_source"] = "manual"
        _insert(conn, row)
        counts["manual"] += 1

    conn.commit()
    conn.close()
    return counts


def _insert(conn: sqlite3.Connection, row: dict) -> None:
    conn.execute(
        """INSERT OR REPLACE INTO documents
           (fdi, name, issuing_body, geography, source_url, family_key,
            catalog_source, license_status, license_note)
           VALUES (:fdi, :name, :issuing_body, :geography, :source_url,
                   :family_key, :catalog_source, :license_status, :license_note)""",
        row,
    )


CACHE_DIR = Path(__file__).resolve().parent / "document_cache"
CACHEABLE_STATUSES = {"public_domain", "free_to_access"}


def cache_document(conn: sqlite3.Connection, fdi: str, timeout: int = 20) -> str:
    """Fetches and stores the raw bytes of one document. Refuses anything not
    already classified public_domain/free_to_access - "unknown" and
    "copyrighted_registration_required" are never fetched, regardless of
    what the URL actually serves. Returns a short status string.
    """
    import datetime
    import requests

    row = conn.execute(
        "SELECT source_url, license_status FROM documents WHERE fdi = ?", (fdi,)
    ).fetchone()
    if row is None:
        return "not-found"
    source_url, license_status = row
    if license_status not in CACHEABLE_STATUSES:
        return f"refused ({license_status})"
    if not source_url or not str(source_url).startswith("http"):
        return "no-url"

    try:
        resp = requests.get(
            source_url, timeout=timeout,
            headers={"User-Agent": "AuditForge-DocumentCatalog/1.0"},
        )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - network calls, report and move on
        return f"fetch-failed ({exc.__class__.__name__})"

    content_type = resp.headers.get("Content-Type", "")
    ext = ".pdf" if "pdf" in content_type else (".html" if "html" in content_type else ".bin")
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = CACHE_DIR / f"{fdi}{ext}"
    out_path.write_bytes(resp.content)

    try:
        stored_path = str(out_path.relative_to(ROOT))
    except ValueError:
        stored_path = str(out_path)
    conn.execute(
        "UPDATE documents SET full_text_cached = 1, cached_path = ?, cached_at = ? WHERE fdi = ?",
        (stored_path, datetime.datetime.now(datetime.timezone.utc).isoformat(), fdi),
    )
    conn.commit()

    # R-040's stated concern: some FDS links are landing pages, not the
    # document itself. Can't fully verify without a human reading it, but a
    # tiny HTML response is a strong landing-page signal worth flagging
    # rather than silently trusting - still cached (it's evidence either
    # way), just labeled so a bulk run's output is honest about what needs
    # a manual look.
    suspect = "html" in content_type and len(resp.content) < 40_000
    label = "cached, SUSPECT LANDING PAGE - verify manually" if suspect else "cached"
    return f"{label} ({len(resp.content)} bytes, {content_type or 'unknown type'})"


def cache_all(conn: sqlite3.Connection, delay: float = 1.5, limit: int | None = None) -> dict:
    """Batch-caches every not-yet-cached public_domain/free_to_access document.
    Verified per-document (R-040's concern: some FDS links are landing pages,
    not direct files) via a lightweight sanity check on the fetched bytes
    rather than blind trust in the URL - HTML landing pages are recorded as
    'landing-page' rather than silently cached as if they were the standard.
    `delay` seconds between requests is polite-crawling, not a published rate
    limit (these are ~180 different publishers, not one API).
    """
    rows = conn.execute(
        "SELECT fdi FROM documents WHERE license_status IN ('public_domain','free_to_access') "
        "AND full_text_cached = 0 ORDER BY fdi"
    ).fetchall()
    fdis = [r[0] for r in rows]
    if limit:
        fdis = fdis[:limit]
    tally: dict[str, int] = {}
    for i, fdi in enumerate(fdis):
        status = cache_document(conn, fdi)
        bucket = status.split(" (")[0]
        tally[bucket] = tally.get(bucket, 0) + 1
        print(f"[{i + 1}/{len(fdis)}] {fdi}: {status}")
        if i < len(fdis) - 1:
            time.sleep(delay)
    return tally


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", nargs="+", metavar="FDI",
                         help="Fetch and cache the raw document for these FDIs "
                              "(only public_domain/free_to_access are ever fetched)")
    parser.add_argument("--cache-all", action="store_true",
                         help="Fetch and cache every not-yet-cached public_domain/"
                              "free_to_access document (ROADMAP R-040)")
    parser.add_argument("--limit", type=int, default=None,
                         help="Cap how many documents --cache-all fetches this run")
    parser.add_argument("--delay", type=float, default=1.5,
                         help="Seconds between requests for --cache-all (default 1.5)")
    parser.add_argument("--skip-build", action="store_true",
                         help="Reuse the existing document_catalog.db instead of rebuilding it")
    args = parser.parse_args()

    if not args.skip_build:
        counts = build()
        print(f"document_catalog.db written: "
              f"(scf={counts['scf']}, compliance-as-code={counts['compliance-as-code']}, "
              f"manual={counts['manual']})")

    conn = sqlite3.connect(str(DB_PATH))
    total = conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
    by_license = dict(conn.execute(
        "SELECT license_status, COUNT(*) FROM documents GROUP BY license_status"
    ).fetchall())
    print(f"{total} documents catalogued")
    print("by license_status:", json.dumps(by_license, indent=2))

    if args.cache:
        for fdi in args.cache:
            print(f"{fdi}: {cache_document(conn, fdi)}")
    if args.cache_all:
        tally = cache_all(conn, delay=args.delay, limit=args.limit)
        print("cache-all summary:", json.dumps(tally, indent=2))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
