"""Tests for mcp_server.py's tool functions. Uses a small fixture
vector_index.db built with real sqlite-vec (not a mock) so the actual KNN/
partition-key query logic is exercised, but stubs out the embedding model
(deterministic hash-based vectors) so tests run fast and offline - no
130MB model download required.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqlite_vec  # noqa: E402
import mcp_server  # noqa: E402

DIM = 4


def _fake_vec(text: str):
    """Deterministic 4-dim 'embedding' from a string, just for exercising
    KNN/distance ordering in tests - not a real embedding."""
    h = sum(ord(c) for c in text)
    return [
        (h % 7) / 7.0, (h % 11) / 11.0, (h % 13) / 13.0, (h % 17) / 17.0,
    ]


def _build_fixture_index(path: Path):
    conn = sqlite3.connect(str(path))
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)
    conn.executescript(
        """
        CREATE TABLE controls_meta (rowid INTEGER PRIMARY KEY, control_id TEXT, framework TEXT, text TEXT);
        CREATE TABLE documents_meta (rowid INTEGER PRIMARY KEY, fdi TEXT, chunk_index INTEGER, source TEXT, text TEXT);
        CREATE TABLE scf_crosswalk_tokens (token TEXT, scf_family TEXT, scf_id TEXT);
        CREATE INDEX idx_scf_tokens_token ON scf_crosswalk_tokens(token);
        """
    )
    # DIM is a hardcoded int constant (test-only vector size), not
    # attacker-controlled input; SQLite DDL has no bind-parameter syntax for
    # a vec0 column's declared dimension, so f-string interpolation is the
    # only way to express this (see build_vector_index.py for the identical
    # real, non-test pattern).
    conn.execute(f"CREATE VIRTUAL TABLE controls_vec USING vec0(embedding float[{DIM}], framework text partition key)")  # soc2-ignore: DIM is a constant, not input; sqlite DDL can't bind this
    conn.execute(f"CREATE VIRTUAL TABLE documents_vec USING vec0(embedding float[{DIM}], fdi text partition key)")  # soc2-ignore: DIM is a constant, not input; sqlite DDL can't bind this

    rows = [
        ("CC6.1", "SOC2", "Logical access controls restrict system access."),
        ("AC-2", "NIST53", "The organization manages information system accounts."),
        ("A.9.2.1", "ISO27001", "User registration and de-registration process."),
        # SCF-crosswalk-derived families (R-047 fixture): both share the
        # scf_id "IAC-01" for the same underlying SCF control.
        ("IAC-01", "SCF_GENERAL_ISO_27001_2022", "9.2.1"),
        ("IAC-01", "SCF_GENERAL_NIST_800_53_R5", "AC-2 AC-2(1)"),
    ]
    for i, (cid, fw, text) in enumerate(rows, start=1):
        conn.execute("INSERT INTO controls_meta (rowid, control_id, framework, text) VALUES (?, ?, ?, ?)", (i, cid, fw, text))
        conn.execute(
            "INSERT INTO controls_vec (rowid, embedding, framework) VALUES (?, ?, ?)",
            (i, sqlite_vec.serialize_float32(_fake_vec(text)), fw),
        )
    for token, scf_family, scf_id in [("AC-2", "SCF_GENERAL_NIST_800_53_R5", "IAC-01"),
                                        ("AC-2(1)", "SCF_GENERAL_NIST_800_53_R5", "IAC-01")]:
        conn.execute("INSERT INTO scf_crosswalk_tokens (token, scf_family, scf_id) VALUES (?, ?, ?)",
                     (token, scf_family, scf_id))

    doc_rows = [("fdi-1", 0, "cached_text", "Access control policy document text.")]
    for i, (fdi, chunk_idx, source, text) in enumerate(doc_rows, start=1):
        conn.execute("INSERT INTO documents_meta (rowid, fdi, chunk_index, source, text) VALUES (?, ?, ?, ?, ?)", (i, fdi, chunk_idx, source, text))
        conn.execute(
            "INSERT INTO documents_vec (rowid, embedding, fdi) VALUES (?, ?, ?)",
            (i, sqlite_vec.serialize_float32(_fake_vec(text)), fdi),
        )
    conn.commit()
    return conn


def test_search_controls_returns_ranked_results(tmp_path, monkeypatch):
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: sqlite_vec.serialize_float32(_fake_vec("Logical access controls restrict system access.")))

    result = mcp_server.search_controls("access control", top_k=2)
    assert len(result["results"]) == 2
    assert result["results"][0]["control_id"] == "CC6.1"  # exact text match -> distance 0


def test_search_controls_framework_filter_uses_partition_key(tmp_path, monkeypatch):
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: sqlite_vec.serialize_float32(_fake_vec("anything")))

    result = mcp_server.search_controls("q", framework="NIST53", top_k=5)
    assert all(r["framework"] == "NIST53" for r in result["results"])
    assert len(result["results"]) == 1


def test_get_control_found_and_not_found(tmp_path, monkeypatch):
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)

    found = mcp_server.get_control("CC6.1", "SOC2")
    assert found["found"] is True
    assert "Logical access" in found["text"]

    missing = mcp_server.get_control("ZZ-999", "SOC2")
    assert missing["found"] is False


def test_search_documents(tmp_path, monkeypatch):
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: sqlite_vec.serialize_float32(_fake_vec("q")))

    result = mcp_server.search_documents("policy", top_k=1)
    assert result["results"][0]["fdi"] == "fdi-1"


def test_crosswalk_control_finds_nearest_in_target_framework(tmp_path, monkeypatch):
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: sqlite_vec.serialize_float32(_fake_vec(q)))

    result = mcp_server.crosswalk_control("CC6.1", "SOC2", "ISO27001", top_k=1)
    assert result["found"] is True
    assert result["method"] == "semantic_similarity"
    assert result["candidates"][0]["control_id"] == "A.9.2.1"


def test_crosswalk_control_exact_scf_direct(tmp_path, monkeypatch):
    # R-047: both source and target are SCF_* families sharing the same
    # scf_id - must be a direct exact lookup (distance 0), no embedding call.
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: (_ for _ in ()).throw(AssertionError("should not embed for exact_scf_direct")))

    result = mcp_server.crosswalk_control("IAC-01", "SCF_GENERAL_NIST_800_53_R5", "SCF_GENERAL_ISO_27001_2022")
    assert result["found"] is True
    assert result["method"] == "exact_scf_direct"
    assert result["candidates"] == [{"control_id": "IAC-01", "text": "9.2.1", "distance": 0.0}]


def test_crosswalk_control_exact_scf_token_join(tmp_path, monkeypatch):
    # R-047: source is a real standard (NIST53:AC-2), target is SCF_* -
    # must join through the token index, not semantic similarity.
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: (_ for _ in ()).throw(AssertionError("should not embed for exact_scf_token_join")))

    result = mcp_server.crosswalk_control("AC-2", "NIST53", "SCF_GENERAL_ISO_27001_2022")
    assert result["found"] is True
    assert result["method"] == "exact_scf_token_join"
    assert len(result["candidates"]) == 1
    candidate = result["candidates"][0]
    assert candidate["control_id"] == "IAC-01"
    assert candidate["text"] == "9.2.1"
    assert candidate["matched_via"] == "SCF_GENERAL_NIST_800_53_R5"


def test_crosswalk_control_token_join_no_match(tmp_path, monkeypatch):
    conn = _build_fixture_index(tmp_path / "vector_index.db")
    monkeypatch.setattr(mcp_server, "_vec_conn", conn)
    monkeypatch.setattr(mcp_server, "_embed_query", lambda q: (_ for _ in ()).throw(AssertionError("should not embed")))

    result = mcp_server.crosswalk_control("AC-2", "NIST53", "SCF_GENERAL_NOWHERE")
    assert result["found"] is True
    assert result["method"] == "exact_scf_token_join"
    assert result["candidates"] == []


def test_list_frameworks_counts_controls(tmp_path, monkeypatch):
    fake_metadata = {
        "frameworks": {"SOC2": "SOC 2 Common Criteria", "NIST53": "NIST SP 800-53 Rev5"},
        "controls": {"SOC2:CC6.1": "x", "SOC2:CC6.2": "y", "NIST53:AC-2": "z"},
    }
    metadata_path = tmp_path / "framework_metadata.json"
    metadata_path.write_text(json.dumps(fake_metadata), encoding="utf-8")
    monkeypatch.setattr(mcp_server, "FRAMEWORK_METADATA_PATH", metadata_path)

    result = mcp_server.list_frameworks()
    by_prefix = {f["prefix"]: f for f in result["frameworks"]}
    assert by_prefix["SOC2"]["control_count"] == 2
    assert by_prefix["NIST53"]["control_count"] == 1


def test_crosswalk_rule_found_and_not_found(tmp_path, monkeypatch):
    mappings_path = tmp_path / "framework_mappings.json"
    mappings_path.write_text(json.dumps({"mappings": {"SEC001": [{"framework": "SOC2", "control": "CC6.1"}]}}), encoding="utf-8")
    monkeypatch.setattr(mcp_server, "FRAMEWORK_MAPPINGS_PATH", mappings_path)

    found = mcp_server.crosswalk_rule("SEC001")
    assert found["found"] is True
    assert found["frameworks"][0]["framework"] == "SOC2"

    missing = mcp_server.crosswalk_rule("NOPE999")
    assert missing["found"] is False


def test_get_document_found_and_not_found(tmp_path, monkeypatch):
    db_path = tmp_path / "document_catalog.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE documents (fdi TEXT, name TEXT, issuing_body TEXT, geography TEXT, "
        "source_url TEXT, license_status TEXT, license_note TEXT, full_text_cached INTEGER, cached_path TEXT)"
    )
    conn.execute(
        "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("fdi-1", "Test Standard", "Test Body", "US", "https://example.gov/doc", "public_domain", "note", 1, "scripts/document_cache/fdi-1.pdf"),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(mcp_server, "DOCUMENT_CATALOG_PATH", db_path)

    found = mcp_server.get_document("fdi-1")
    assert found["found"] is True
    assert found["name"] == "Test Standard"

    missing = mcp_server.get_document("no-such-fdi")
    assert missing["found"] is False


def test_kev_lookup_wraps_vuln_intel():
    with patch("mcp_server.vuln_intel.check_kev", return_value={"cveID": "CVE-2024-3400"}):
        result = mcp_server.kev_lookup("cve-2024-3400")
    assert result["known_exploited"] is True
    assert result["cve"] == "CVE-2024-3400"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
