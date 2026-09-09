"""Tests for build_vector_index.py's pure logic (chunking, text extraction,
control-text iteration) - the parts that don't require loading the embedding
model or a real vector_index.db, so these run fast in CI without pulling a
130MB model off HuggingFace.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_vector_index as bvi  # noqa: E402


def test_chunk_splits_long_text_with_overlap():
    text = "word " * 1000  # 5000 chars
    chunks = bvi._chunk(text)
    assert len(chunks) > 1
    assert all(len(c) <= bvi.CHUNK_CHARS for c in chunks)


def test_chunk_empty_text_returns_no_chunks():
    assert bvi._chunk("") == []
    assert bvi._chunk("   \n\t  ") == []


def test_chunk_short_fragment_dropped():
    assert bvi._chunk("hi") == []


def test_chunk_respects_max_chunks_cap(monkeypatch):
    monkeypatch.setattr(bvi, "MAX_CHUNKS_PER_DOC", 3)
    text = "word " * 10000
    chunks = bvi._chunk(text)
    assert len(chunks) == 3


def test_extract_text_html_strips_tags_and_scripts(tmp_path):
    html_path = tmp_path / "doc.html"
    html_path.write_text(
        "<html><head><style>.a{color:red}</style></head>"
        "<body><script>alert(1)</script><p>Real content here &amp; more.</p></body></html>",
        encoding="utf-8",
    )
    text = bvi._extract_text(html_path)
    assert "Real content here & more." in text
    assert "alert" not in text
    assert "color:red" not in text


def test_extract_text_plain_txt_passthrough(tmp_path):
    txt_path = tmp_path / "doc.txt"
    txt_path.write_text("plain text content", encoding="utf-8")
    assert bvi._extract_text(txt_path) == "plain text content"


def test_iter_control_texts_reads_metadata_json(tmp_path, monkeypatch):
    fake_metadata = {
        "frameworks": {"SOC2": "SOC 2 Common Criteria"},
        "controls": {"SOC2:CC6.1": "Logical access controls are implemented."},
    }
    metadata_path = tmp_path / "framework_metadata.json"
    metadata_path.write_text(json.dumps(fake_metadata), encoding="utf-8")
    monkeypatch.setattr(bvi, "METADATA_PATH", metadata_path)

    rows = list(bvi._iter_control_texts())
    assert len(rows) == 1
    control_id, framework, description, embed_text = rows[0]
    assert control_id == "CC6.1"
    assert framework == "SOC2"
    assert description == "Logical access controls are implemented."
    assert "SOC 2 Common Criteria" in embed_text
    assert "Logical access controls" in embed_text


def test_iter_document_texts_uses_metadata_fallback_when_uncached(tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "document_catalog.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE documents (fdi TEXT, name TEXT, issuing_body TEXT, "
        "full_text_cached INTEGER, cached_path TEXT)"
    )
    conn.execute(
        "INSERT INTO documents VALUES (?, ?, ?, ?, ?)",
        ("test-fdi", "Test Standard", "Test Body", 0, None),
    )
    conn.commit()
    conn.close()
    monkeypatch.setattr(bvi, "DOCUMENT_CATALOG_PATH", db_path)

    rows = list(bvi._iter_document_texts())
    assert len(rows) == 1
    fdi, _chunk_index, source, text = rows[0]
    assert fdi == "test-fdi"
    assert source == "metadata_only"
    assert "Test Standard" in text


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
