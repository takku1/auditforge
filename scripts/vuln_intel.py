#!/usr/bin/env python3
"""Free, no-auth-required vulnerability intelligence, cached locally in
scripts/vuln_intel_cache.db so repeated lookups (from the MCP server, from
universal_audit.py, from a human at the CLI) don't re-hit the network or
blow through rate limits.

Three sources, all free/open, none requiring a paid tier:
  - CISA KEV: the authoritative "is this CVE actively being exploited in the
    wild" catalog. No auth. Whole-catalog JSON, refreshed on a TTL.
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - FIRST.org EPSS: daily-updated probability (0-1) that a CVE will be
    exploited in the next 30 days. No auth.
    https://api.first.org/data/v1/epss
  - NVD API 2.0: CVE detail (CVSS, description, references). No auth required
    for basic use (5 req/30s); an optional free NVD_API_KEY env var raises
    that to 50 req/30s. https://services.nvd.nist.gov/rest/json/cves/2.0

This is deliberately the "is this finding actually urgent" layer on top of
audit_repo.py / universal_audit.py's OSV-based dependency scanning - OSV says
a package has a known vulnerability; KEV/EPSS says whether that vulnerability
is one anyone is actually exploiting, which is what SOC 2 risk-based
remediation prioritization language (CC7.1/CC7.2) actually asks for.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
import time
from pathlib import Path

import requests

DB_PATH = Path(__file__).resolve().parent / "vuln_intel_cache.db"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

KEV_TTL = datetime.timedelta(hours=12)
EPSS_TTL = datetime.timedelta(hours=20)  # EPSS publishes once/day
NVD_TTL = datetime.timedelta(days=7)     # CVE detail is near-static once published

USER_AGENT = "AuditForge-VulnIntel/1.0"

SCHEMA = """
CREATE TABLE IF NOT EXISTS kev_catalog (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS epss_scores (
    cve TEXT PRIMARY KEY,
    epss REAL,
    percentile REAL,
    score_date TEXT,
    fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nvd_cves (
    cve TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
"""


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)
    return conn


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _stale(fetched_at: str, ttl: datetime.timedelta) -> bool:
    try:
        ts = datetime.datetime.fromisoformat(fetched_at)
    except ValueError:
        return True
    return _now() - ts > ttl


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------

def _refresh_kev(conn: sqlite3.Connection, timeout: int = 20) -> None:
    resp = requests.get(KEV_URL, timeout=timeout, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    conn.execute(
        "INSERT INTO kev_catalog (id, payload, fetched_at) VALUES (1, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, fetched_at = excluded.fetched_at",
        (resp.text, _now().isoformat()),
    )
    conn.commit()


def check_kev(cve_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
    """Returns the KEV entry for cve_id, or None if it isn't in the catalog.
    Fetches/refreshes the whole catalog (one HTTP call) at most once per KEV_TTL.
    """
    own = conn is None
    conn = conn or _conn()
    try:
        row = conn.execute("SELECT payload, fetched_at FROM kev_catalog WHERE id = 1").fetchone()
        if row is None or _stale(row[1], KEV_TTL):
            try:
                _refresh_kev(conn)
                row = conn.execute("SELECT payload, fetched_at FROM kev_catalog WHERE id = 1").fetchone()
            except Exception as exc:  # noqa: BLE001 - fall back to stale cache if offline
                if row is None:
                    raise RuntimeError(f"KEV fetch failed and no cache available: {exc}") from exc
        catalog = json.loads(row[0])
        cve_id = cve_id.strip().upper()
        for vuln in catalog.get("vulnerabilities", []):
            if vuln.get("cveID", "").upper() == cve_id:
                return vuln
        return None
    finally:
        if own:
            conn.close()


def kev_catalog_ids(conn: sqlite3.Connection | None = None) -> tuple[list[str], str | None]:
    """Sorted KEV CVE IDs plus the catalog's fetched_at timestamp.

    Refreshes the whole catalog (one HTTP call) when the cache is empty or
    older than KEV_TTL; falls back to the stale cache when offline. Raises
    RuntimeError only when offline with no cache at all. Used by
    check_freshness.py's KEV-diff watch (newly exploited CVEs over time).
    """
    own = conn is None
    conn = conn or _conn()
    try:
        row = conn.execute("SELECT payload, fetched_at FROM kev_catalog WHERE id = 1").fetchone()
        if row is None or _stale(row[1], KEV_TTL):
            try:
                _refresh_kev(conn)
                row = conn.execute("SELECT payload, fetched_at FROM kev_catalog WHERE id = 1").fetchone()
            except Exception as exc:  # noqa: BLE001 - fall back to stale cache if offline
                if row is None:
                    raise RuntimeError(f"KEV fetch failed and no cache available: {exc}") from exc
        catalog = json.loads(row[0])
        ids = sorted({(v.get("cveID") or "").strip().upper()
                      for v in catalog.get("vulnerabilities", []) if v.get("cveID")})
        return ids, row[1]
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------
# FIRST.org EPSS
# --------------------------------------------------------------------------

def get_epss(cve_ids: list[str], conn: sqlite3.Connection | None = None, timeout: int = 20) -> dict[str, dict]:
    """Returns {cve: {epss, percentile, date}} for each requested CVE.
    Batches up to 100 CVEs per HTTP call (EPSS API's documented comma-join
    support); per-CVE results are cached individually with their own TTL.
    """
    own = conn is None
    conn = conn or _conn()
    try:
        cve_ids = [c.strip().upper() for c in cve_ids if c and c.strip()]
        results: dict[str, dict] = {}
        need: list[str] = []
        for cve in cve_ids:
            row = conn.execute(
                "SELECT epss, percentile, score_date, fetched_at FROM epss_scores WHERE cve = ?", (cve,)
            ).fetchone()
            if row and not _stale(row[3], EPSS_TTL):
                results[cve] = {"epss": row[0], "percentile": row[1], "date": row[2]}
            else:
                need.append(cve)

        for i in range(0, len(need), 100):
            batch = need[i:i + 100]
            resp = requests.get(
                EPSS_URL, params={"cve": ",".join(batch)}, timeout=timeout,
                headers={"User-Agent": USER_AGENT},
            )
            resp.raise_for_status()
            data = resp.json().get("data", [])
            fetched_at = _now().isoformat()
            found = set()
            for entry in data:
                cve = entry["cve"].upper()
                found.add(cve)
                epss = float(entry["epss"])
                pct = float(entry["percentile"])
                date = entry.get("date")
                conn.execute(
                    "INSERT INTO epss_scores (cve, epss, percentile, score_date, fetched_at) VALUES (?, ?, ?, ?, ?) "
                    "ON CONFLICT(cve) DO UPDATE SET epss=excluded.epss, percentile=excluded.percentile, "
                    "score_date=excluded.score_date, fetched_at=excluded.fetched_at",
                    (cve, epss, pct, date, fetched_at),
                )
                results[cve] = {"epss": epss, "percentile": pct, "date": date}
            conn.commit()
            # CVEs FIRST.org has no score for yet (too new / withdrawn) - don't
            # re-request every call, cache a null result for one EPSS_TTL window.
            for cve in batch:
                if cve not in found:
                    conn.execute(
                        "INSERT INTO epss_scores (cve, epss, percentile, score_date, fetched_at) VALUES (?, NULL, NULL, NULL, ?) "
                        "ON CONFLICT(cve) DO UPDATE SET fetched_at=excluded.fetched_at",
                        (cve, fetched_at),
                    )
            conn.commit()
        return results
    finally:
        if own:
            conn.close()


# --------------------------------------------------------------------------
# NVD API 2.0
# --------------------------------------------------------------------------

def get_nvd_detail(cve_id: str, conn: sqlite3.Connection | None = None, timeout: int = 20) -> dict | None:
    """CVE detail (CVSS vector/score, description, references) from NVD.
    Uses NVD_API_KEY from the environment if set (50 req/30s vs 5 req/30s
    without one - still free, just requires signing up once).
    """
    own = conn is None
    conn = conn or _conn()
    try:
        cve_id = cve_id.strip().upper()
        row = conn.execute("SELECT payload, fetched_at FROM nvd_cves WHERE cve = ?", (cve_id,)).fetchone()
        if row and not _stale(row[1], NVD_TTL):
            return json.loads(row[0])

        api_key = os.environ.get("NVD_API_KEY")
        headers = {"User-Agent": USER_AGENT}
        if api_key:
            headers["apiKey"] = api_key
        resp = requests.get(NVD_URL, params={"cveId": cve_id}, timeout=timeout, headers=headers)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return None
        detail = vulns[0].get("cve", {})
        conn.execute(
            "INSERT INTO nvd_cves (cve, payload, fetched_at) VALUES (?, ?, ?) "
            "ON CONFLICT(cve) DO UPDATE SET payload=excluded.payload, fetched_at=excluded.fetched_at",
            (cve_id, json.dumps(detail), _now().isoformat()),
        )
        conn.commit()
        # Unauthenticated NVD calls are rate-limited to 5/30s; a small sleep
        # keeps a caller doing several lookups in a row from tripping it.
        if not api_key:
            time.sleep(6)
        return detail
    finally:
        if own:
            conn.close()


def enrich_cve(cve_id: str) -> dict:
    """One-stop lookup combining all three sources for a single CVE - the
    shape the MCP server and universal_audit.py's finding-enrichment both want.
    """
    conn = _conn()
    try:
        kev = check_kev(cve_id, conn)
        epss = get_epss([cve_id], conn).get(cve_id.strip().upper())
        return {
            "cve": cve_id.strip().upper(),
            "known_exploited": kev is not None,
            "kev_detail": kev,
            "epss": epss,
        }
    finally:
        conn.close()


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kev", metavar="CVE", help="Check CISA KEV for one CVE")
    parser.add_argument("--epss", metavar="CVE", help="Comma-separated CVE list for EPSS scores")
    parser.add_argument("--nvd", metavar="CVE", help="Fetch NVD detail for one CVE")
    parser.add_argument("--enrich", metavar="CVE", help="KEV + EPSS combined for one CVE")
    args = parser.parse_args()

    if args.kev:
        print(json.dumps(check_kev(args.kev), indent=2))
    if args.epss:
        print(json.dumps(get_epss(args.epss.split(",")), indent=2))
    if args.nvd:
        print(json.dumps(get_nvd_detail(args.nvd), indent=2))
    if args.enrich:
        print(json.dumps(enrich_cve(args.enrich), indent=2))
    if not any([args.kev, args.epss, args.nvd, args.enrich]):
        parser.print_help()
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
