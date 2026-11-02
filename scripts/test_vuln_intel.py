"""Tests for vuln_intel.py - CISA KEV / FIRST.org EPSS / NVD client with a
local SQLite cache. Network calls are mocked; only the caching logic,
TTL/staleness handling, and response parsing are under test here (the live
APIs themselves are exercised manually via `python scripts/vuln_intel.py`).
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vuln_intel  # noqa: E402


def _mem_conn():
    conn = sqlite3.connect(":memory:")
    conn.executescript(vuln_intel.SCHEMA)
    return conn


def _fake_response(json_body=None, text_body=None, status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.raise_for_status = MagicMock()
    if status >= 400:
        resp.raise_for_status.side_effect = Exception(f"HTTP {status}")
    if json_body is not None:
        resp.json.return_value = json_body
    if text_body is not None:
        resp.text = text_body
    return resp


KEV_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto", "knownRansomwareCampaignUse": "Known"},
    ]
}


def test_check_kev_hit():
    conn = _mem_conn()
    with patch("vuln_intel.requests.get", return_value=_fake_response(text_body=json.dumps(KEV_PAYLOAD))):
        result = vuln_intel.check_kev("CVE-2024-3400", conn)
    assert result is not None
    assert result["vendorProject"] == "Palo Alto"


def test_check_kev_miss():
    conn = _mem_conn()
    with patch("vuln_intel.requests.get", return_value=_fake_response(text_body=json.dumps(KEV_PAYLOAD))):
        result = vuln_intel.check_kev("CVE-1999-0001", conn)
    assert result is None


def test_check_kev_uses_cache_within_ttl():
    conn = _mem_conn()
    mock_get = MagicMock(return_value=_fake_response(text_body=json.dumps(KEV_PAYLOAD)))
    with patch("vuln_intel.requests.get", mock_get):
        vuln_intel.check_kev("CVE-2024-3400", conn)
        vuln_intel.check_kev("CVE-2024-3400", conn)
    assert mock_get.call_count == 1  # second call served from cache, no refetch


def test_check_kev_refreshes_when_stale():
    conn = _mem_conn()
    stale_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=13)).isoformat()
    conn.execute(
        "INSERT INTO kev_catalog (id, payload, fetched_at) VALUES (1, ?, ?)",
        (json.dumps({"vulnerabilities": []}), stale_ts),
    )
    conn.commit()
    with patch("vuln_intel.requests.get", return_value=_fake_response(text_body=json.dumps(KEV_PAYLOAD))) as mock_get:
        result = vuln_intel.check_kev("CVE-2024-3400", conn)
    assert mock_get.called
    assert result is not None


EPSS_PAYLOAD = {
    "data": [
        {"cve": "CVE-2024-3400", "epss": "0.99999", "percentile": "1.00000", "date": "2026-09-08"},
    ]
}


def test_get_epss_caches_and_returns_scores():
    conn = _mem_conn()
    with patch("vuln_intel.requests.get", return_value=_fake_response(json_body=EPSS_PAYLOAD)):
        result = vuln_intel.get_epss(["CVE-2024-3400"], conn)
    assert result["CVE-2024-3400"]["epss"] == 0.99999
    row = conn.execute("SELECT epss FROM epss_scores WHERE cve = ?", ("CVE-2024-3400",)).fetchone()
    assert row is not None


def test_get_epss_no_score_cached_as_null_not_refetched():
    conn = _mem_conn()
    mock_get = MagicMock(return_value=_fake_response(json_body={"data": []}))
    with patch("vuln_intel.requests.get", mock_get):
        result = vuln_intel.get_epss(["CVE-9999-9999"], conn)
        assert "CVE-9999-9999" not in result
        vuln_intel.get_epss(["CVE-9999-9999"], conn)
    assert mock_get.call_count == 1  # cached null result, not refetched within TTL


NVD_PAYLOAD = {
    "vulnerabilities": [
        {"cve": {"id": "CVE-2024-3400", "descriptions": [{"lang": "en", "value": "PAN-OS command injection"}]}}
    ]
}


def test_get_nvd_detail_caches():
    conn = _mem_conn()
    with patch("vuln_intel.requests.get", return_value=_fake_response(json_body=NVD_PAYLOAD)), \
         patch("vuln_intel.time.sleep"):
        detail = vuln_intel.get_nvd_detail("CVE-2024-3400", conn)
    assert detail["id"] == "CVE-2024-3400"
    row = conn.execute("SELECT payload FROM nvd_cves WHERE cve = ?", ("CVE-2024-3400",)).fetchone()
    assert row is not None


def test_get_nvd_detail_404_returns_none():
    conn = _mem_conn()
    with patch("vuln_intel.requests.get", return_value=_fake_response(status=404)):
        detail = vuln_intel.get_nvd_detail("CVE-0000-0000", conn)
    assert detail is None


def test_enrich_cve_combines_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(vuln_intel, "DB_PATH", tmp_path / "cache.db")
    with patch("vuln_intel.requests.get") as mock_get:
        mock_get.side_effect = [
            _fake_response(text_body=json.dumps(KEV_PAYLOAD)),
            _fake_response(json_body=EPSS_PAYLOAD),
        ]
        result = vuln_intel.enrich_cve("CVE-2024-3400")
    assert result["known_exploited"] is True
    assert result["epss"]["epss"] == 0.99999


def test_kev_catalog_ids_sorted_and_cached():
    conn = _mem_conn()
    payload = {"vulnerabilities": [
        {"cveID": "CVE-2024-0002"}, {"cveID": "CVE-2024-0001"},
        {"cveID": "CVE-2024-0001"}, {"cveID": ""},
    ]}
    with patch("vuln_intel.requests.get",
               return_value=_fake_response(text_body=json.dumps(payload))):
        ids, fetched_at = vuln_intel.kev_catalog_ids(conn)
    assert ids == ["CVE-2024-0001", "CVE-2024-0002"]
    assert fetched_at is not None
    # second call uses cache - no HTTP
    with patch("vuln_intel.requests.get",
               side_effect=AssertionError("must not refetch")):
        ids2, _ = vuln_intel.kev_catalog_ids(conn)
    assert ids2 == ids


def test_kev_catalog_ids_offline_no_cache_raises():
    conn = _mem_conn()
    with patch("vuln_intel.requests.get",
               side_effect=Exception("no route")):
        try:
            vuln_intel.kev_catalog_ids(conn)
        except RuntimeError as exc:
            assert "no cache" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
