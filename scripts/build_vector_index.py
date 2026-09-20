#!/usr/bin/env python3
"""Builds scripts/vector_index.db - a local, dependency-free (at query time)
semantic search index over every control in framework_metadata.json and every
cached document in document_catalog.db.

Fully derived, like framework_metadata.json and document_catalog.db -
regenerate via this script, never hand-edit.

Why sqlite-vec instead of a server-shaped vector DB (Chroma/Qdrant/Pinecone):
this project's whole ethos is dependency-free, single-file, run-entirely-
locally tooling (see audit_repo.py). sqlite-vec is a SQLite extension - the
vectors live in a plain .db file right next to document_catalog.db, there is
no service to start, and a query is a single `SELECT ... WHERE embedding
MATCH ? ORDER BY distance LIMIT k` - sub-millisecond at this corpus size
(~42k controls), which matters because the MCP server (scripts/mcp_server.py)
calls this on every search_controls() request.

Embeddings: BAAI/bge-small-en-v1.5 via sentence-transformers - 384 dims,
~130MB, CPU-only, no GPU/Ollama daemon required, ~800-1000 sentences/sec on a
laptop CPU. bge models are asymmetric: passages (control/document text) are
embedded as-is; queries get a "Represent this sentence for searching relevant
passages: " prefix at search time (see mcp_server.py's search_controls). Set
EMBEDDING_MODEL to override.

Token-cost note: this whole file exists so an agent's semantic search never
has to load framework_metadata.json's ~3.2MB (or the full document corpus)
into its own context - retrieval happens here, entirely outside the model,
and only the top-k scoped results (a few hundred tokens) go back to the agent.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
METADATA_PATH = SCRIPTS_DIR / "framework_metadata.json"
DOCUMENT_CATALOG_PATH = SCRIPTS_DIR / "document_catalog.db"
INDEX_PATH = SCRIPTS_DIR / "vector_index.db"
DOCUMENT_CACHE_DIR = SCRIPTS_DIR / "document_cache"

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")
EMBEDDING_DIM = 384
CHUNK_CHARS = 800
CHUNK_OVERLAP = 100
MAX_CHUNKS_PER_DOC = 400  # ~320k chars / doc ceiling, keeps a first pass bounded

SCHEMA = """
CREATE TABLE IF NOT EXISTS controls_meta (
    rowid INTEGER PRIMARY KEY,
    control_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_controls_meta_framework ON controls_meta(framework);
CREATE INDEX IF NOT EXISTS idx_controls_meta_control_id ON controls_meta(control_id);

CREATE TABLE IF NOT EXISTS documents_meta (
    rowid INTEGER PRIMARY KEY,
    fdi TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    source TEXT NOT NULL,  -- 'cached_text' | 'metadata_only'
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_documents_meta_fdi ON documents_meta(fdi);

CREATE TABLE IF NOT EXISTS build_info (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    model TEXT NOT NULL,
    dims INTEGER NOT NULL,
    built_at TEXT NOT NULL,
    control_count INTEGER NOT NULL,
    document_chunk_count INTEGER NOT NULL,
    scf_token_count INTEGER NOT NULL DEFAULT 0
);

-- R-047: exact-match crosswalk through the SCF's own control-ID structure,
-- fixing what semantic search over SCF_* families can't do (their indexed
-- "text" is bare clause numbers, not descriptions - nothing meaningful to
-- embed). Every SCF_* family shares the same scf_id for the same
-- underlying SCF control (e.g. "GOV-01" maps to some ISO 27001 clause AND
-- some NIST 800-53 clause under that identical scf_id) - so tokenizing each
-- family's clause-list value and indexing token -> (family, scf_id) lets a
-- real standard's own control ID (e.g. "AC-2") be joined straight through
-- to any other SCF-mapped standard's clause, deterministically.
CREATE TABLE IF NOT EXISTS scf_crosswalk_tokens (
    token TEXT NOT NULL,
    scf_family TEXT NOT NULL,
    scf_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scf_tokens_token ON scf_crosswalk_tokens(token);

-- R-106: hybrid search. FTS5 keyword table over the same control rows so
-- exact-ID queries ("AC-2", "CWE-79", "SV-230221") hit deterministically
-- instead of hoping the embedding ranks them first. Populated alongside
-- controls_meta (same rowids); queried first by search_controls(), which
-- merges exact hits ahead of vector results. No new dependencies (FTS5
-- ships in stdlib sqlite3) and no extra model calls at query time.
CREATE VIRTUAL TABLE IF NOT EXISTS controls_fts USING fts5(
    control_id, framework, text, tokenize = "unicode61 remove_diacritics 2"
);
"""

_SCF_TOKEN_STRIP = ",;:"


def _tokenize_scf_clause(text: str) -> "list[str]":
    return [t.strip(_SCF_TOKEN_STRIP).upper() for t in text.split() if t.strip(_SCF_TOKEN_STRIP)]


def _load_model():
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(EMBEDDING_MODEL)


def _open_index(fresh: bool) -> sqlite3.Connection:
    import sqlite_vec

    if fresh and INDEX_PATH.exists():
        INDEX_PATH.unlink()
    conn = sqlite3.connect(str(INDEX_PATH))
    conn.enable_load_extension(True)
    sqlite_vec.load(conn)
    conn.enable_load_extension(False)
    conn.executescript(SCHEMA)
    # `framework`/`fdi` are declared as partition keys so a filtered KNN query
    # (search_controls(..., framework="NIST53")) searches within that
    # partition directly, instead of taking the global top-k and filtering
    # afterward - which would silently drop true nearest neighbors that
    # happened to fall outside the unfiltered top-k window.
    conn.execute(
        f"CREATE VIRTUAL TABLE IF NOT EXISTS controls_vec USING vec0("
        f"embedding float[{EMBEDDING_DIM}], framework text partition key)"
    )
    conn.execute(
        f"CREATE VIRTUAL TABLE IF NOT EXISTS documents_vec USING vec0("
        f"embedding float[{EMBEDDING_DIM}], fdi text partition key)"
    )
    return conn


def _iter_control_texts():
    with open(METADATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    frameworks = data.get("frameworks", {})
    for key, description in data.get("controls", {}).items():
        framework, _, control_id = key.partition(":")
        label = frameworks.get(framework, framework)
        embed_text = f"{label} {control_id}: {description}"
        yield control_id, framework, description, embed_text


_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _extract_text(cached_path: Path) -> str:
    suffix = cached_path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            return ""
        try:
            reader = PdfReader(str(cached_path))
            return "\n".join(page.extract_text() or "" for page in reader.pages)
        except Exception:  # noqa: BLE001 - corrupt/encrypted PDFs, skip rather than crash the build
            return ""
    if suffix in (".html", ".htm"):
        raw = cached_path.read_text(encoding="utf-8", errors="ignore")
        raw = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", raw)
        text = _TAG_RE.sub(" ", raw)
        import html as html_module
        return html_module.unescape(text)
    return cached_path.read_text(encoding="utf-8", errors="ignore")


def _chunk(text: str) -> list[str]:
    text = _WS_RE.sub(" ", text).strip()
    if not text:
        return []
    chunks = []
    step = CHUNK_CHARS - CHUNK_OVERLAP
    for i in range(0, len(text), step):
        chunk = text[i:i + CHUNK_CHARS].strip()
        if len(chunk) > 40:  # skip near-empty tail fragments
            chunks.append(chunk)
        if len(chunks) >= MAX_CHUNKS_PER_DOC:
            break
    return chunks


def _iter_document_texts():
    conn = sqlite3.connect(str(DOCUMENT_CATALOG_PATH))
    rows = conn.execute(
        "SELECT fdi, name, issuing_body, full_text_cached, cached_path FROM documents"
    ).fetchall()
    conn.close()
    for fdi, name, issuing_body, cached, cached_path in rows:
        if cached and cached_path:
            full_path = ROOT / cached_path
            if full_path.exists():
                text = _extract_text(full_path)
                chunks = _chunk(text)
                if chunks:
                    for i, chunk in enumerate(chunks):
                        yield fdi, i, "cached_text", f"{name}: {chunk}"
                    continue
        # No usable cached text - still index the metadata so the document
        # is at least findable by name/publisher, rather than absent.
        summary = f"{name} ({issuing_body or 'unknown publisher'})"
        yield fdi, 0, "metadata_only", summary


def build(batch_size: int = 64) -> dict:
    t0 = time.time()
    model = _load_model()
    conn = _open_index(fresh=True)

    control_count = 0
    batch_texts, batch_rows = [], []

    def flush_controls():
        nonlocal control_count
        if not batch_texts:
            return
        import sqlite_vec
        embeddings = model.encode(batch_texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True)
        for (control_id, framework, description), emb in zip(batch_rows, embeddings):
            cur = conn.execute(
                "INSERT INTO controls_meta (control_id, framework, text) VALUES (?, ?, ?)",
                (control_id, framework, description),
            )
            rowid = cur.lastrowid
            conn.execute(
                "INSERT INTO controls_vec (rowid, embedding, framework) VALUES (?, ?, ?)",
                (rowid, sqlite_vec.serialize_float32(emb.tolist()), framework),
            )
            conn.execute(
                "INSERT INTO controls_fts (rowid, control_id, framework, text) VALUES (?, ?, ?, ?)",
                (rowid, control_id, framework, description),
            )
        control_count += len(batch_texts)
        batch_texts.clear()
        batch_rows.clear()

    for control_id, framework, description, embed_text in _iter_control_texts():
        batch_texts.append(embed_text)
        batch_rows.append((control_id, framework, description))
        if len(batch_texts) >= batch_size * 8:
            flush_controls()
    flush_controls()
    conn.commit()
    print(f"[i] controls indexed: {control_count} ({time.time() - t0:.1f}s so far)")

    doc_count = 0
    batch_texts, batch_rows = [], []

    def flush_documents():
        nonlocal doc_count
        if not batch_texts:
            return
        import sqlite_vec
        embeddings = model.encode(batch_texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True)
        for (fdi, chunk_index, source, text), emb in zip(batch_rows, embeddings):
            cur = conn.execute(
                "INSERT INTO documents_meta (fdi, chunk_index, source, text) VALUES (?, ?, ?, ?)",
                (fdi, chunk_index, source, text),
            )
            rowid = cur.lastrowid
            conn.execute(
                "INSERT INTO documents_vec (rowid, embedding, fdi) VALUES (?, ?, ?)",
                (rowid, sqlite_vec.serialize_float32(emb.tolist()), fdi),
            )
        doc_count += len(batch_texts)
        batch_texts.clear()
        batch_rows.clear()

    for fdi, chunk_index, source, text in _iter_document_texts():
        batch_texts.append(text)
        batch_rows.append((fdi, chunk_index, source, text))
        if len(batch_texts) >= batch_size * 8:
            flush_documents()
    flush_documents()
    conn.commit()
    print(f"[i] document chunks indexed: {doc_count}")

    scf_token_count = _build_scf_token_index(conn)
    conn.commit()
    print(f"[i] SCF crosswalk tokens indexed: {scf_token_count}")

    import datetime
    conn.execute(
        "INSERT INTO build_info (id, model, dims, built_at, control_count, document_chunk_count, scf_token_count) "
        "VALUES (1, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
        "model=excluded.model, dims=excluded.dims, built_at=excluded.built_at, "
        "control_count=excluded.control_count, document_chunk_count=excluded.document_chunk_count, "
        "scf_token_count=excluded.scf_token_count",
        (EMBEDDING_MODEL, EMBEDDING_DIM, datetime.datetime.now(datetime.timezone.utc).isoformat(),
         control_count, doc_count, scf_token_count),
    )
    conn.commit()
    conn.close()

    elapsed = time.time() - t0
    print(f"vector_index.db written: {control_count} controls, {doc_count} document chunks, "
          f"{scf_token_count} SCF crosswalk tokens ({elapsed:.1f}s total)")
    return {"controls": control_count, "document_chunks": doc_count,
            "scf_tokens": scf_token_count, "elapsed_s": elapsed}


def _build_scf_token_index(conn) -> int:
    """Populates scf_crosswalk_tokens from every SCF_*-prefixed control
    already inserted into controls_meta this run - see R-047 / the module
    docstring's design note above SCHEMA.
    """
    rows = conn.execute(
        "SELECT control_id, framework, text FROM controls_meta WHERE framework LIKE 'SCF\\_%' ESCAPE '\\'"
    ).fetchall()
    n = 0
    for control_id, framework, text in rows:
        for token in _tokenize_scf_clause(text):
            conn.execute(
                "INSERT INTO scf_crosswalk_tokens (token, scf_family, scf_id) VALUES (?, ?, ?)",
                (token, framework, control_id),
            )
            n += 1
    return n


def main() -> int:
    build()
    return 0


if __name__ == "__main__":
    sys.exit(main())
