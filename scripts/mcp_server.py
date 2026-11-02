#!/usr/bin/env python3
"""AuditForge MCP server - exposes the knowledge base (42k+ controls across
300+ framework families, the document catalog, semantic search, and free
vulnerability intelligence) to any MCP-capable agent as typed tools, instead
of requiring an agent to shell out to CLIs and parse text/JSON by hand.

Design goals (see docs/STATUS.md and the conversation that produced this file
for the full rationale):
  - Fast: control/document lookup and semantic search hit scripts/vector_index.db
    (sqlite-vec) directly - no full-file JSON loads, sub-second at 42k+ rows.
  - Cheap on tokens: every tool returns a small, scoped JSON result (top-k
    matches, one control, one document chunk) - never the full 3.2MB
    framework_metadata.json or a whole cached PDF. Retrieval happens here,
    outside the model's context window, which is the actual token saving -
    not a caching trick on top of dumping everything into context.
  - Read-only: nothing here writes to the derived DBs/JSON at request time.
    Regenerate them with sync_frameworks.py / build_document_catalog.py /
    build_vector_index.py, same as a human would.

Run: python scripts/mcp_server.py  (stdio transport; see ../.mcp.json for how
Claude Code launches this automatically for this project).
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

from mcp.server.mcpserver import MCPServer

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import vuln_intel  # noqa: E402

VECTOR_INDEX_PATH = SCRIPTS_DIR / "vector_index.db"
DOCUMENT_CATALOG_PATH = SCRIPTS_DIR / "document_catalog.db"
FRAMEWORK_METADATA_PATH = SCRIPTS_DIR / "framework_metadata.json"
FRAMEWORK_MAPPINGS_PATH = SCRIPTS_DIR / "framework_mappings.json"
AUDIT_REPO_PATH = SCRIPTS_DIR / "audit_repo.py"

server = MCPServer(
    name="auditforge",
    description="SOC 2 / multi-framework GRC knowledge base and static compliance auditor "
                 "(42k+ controls across 300+ framework families, semantic search, free "
                 "vulnerability intelligence, and the audit_repo.py scanner).",
)

# --------------------------------------------------------------------------
# Lazy singletons - nothing here loads at server startup, only on first use,
# so `python scripts/mcp_server.py` starting up costs ~nothing in tokens/time
# for agent sessions that only ever call e.g. get_control() or run_audit().
# --------------------------------------------------------------------------

_model = None
_vec_conn: sqlite3.Connection | None = None


def _embedding_model():
    global _model
    if _model is None:
        # The model is already cached locally after build_vector_index.py's
        # first run - HF_HUB_OFFLINE skips the ~15 network round-trips
        # sentence-transformers otherwise makes on every load just to
        # re-validate cache freshness. Cuts cold search_controls() latency
        # from ~45s to ~1s and keeps stdout free of HTTP logging noise,
        # which matters here since stdout carries the MCP JSON-RPC stream.
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        from sentence_transformers import SentenceTransformer
        import build_vector_index as bvi
        _model = SentenceTransformer(bvi.EMBEDDING_MODEL)
    return _model


def _vector_conn() -> sqlite3.Connection:
    global _vec_conn
    if _vec_conn is None:
        if not VECTOR_INDEX_PATH.exists():
            raise RuntimeError(
                "vector_index.db not built yet - run: "
                "python scripts/build_vector_index.py"
            )
        import sqlite_vec
        conn = sqlite3.connect(str(VECTOR_INDEX_PATH))
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        _vec_conn = conn
    return _vec_conn


def _embed_query(text: str):
    import sqlite_vec
    # bge-family models are asymmetric: queries need this instruction prefix,
    # passages (already indexed) do not. See build_vector_index.py's header.
    prefixed = f"Represent this sentence for searching relevant passages: {text}"
    vec = _embedding_model().encode([prefixed], normalize_embeddings=True)[0]
    return sqlite_vec.serialize_float32(vec.tolist())


# --------------------------------------------------------------------------
# Hybrid search (R-106)
# --------------------------------------------------------------------------

_FTS_ID_TOKEN = re.compile(r"[A-Za-z0-9]+(?:[._\-()/][A-Za-z0-9]+)+|[A-Za-z0-9]{2,}")


def _fts_exact_matches(conn: sqlite3.Connection, query: str, framework: str | None, limit: int) -> list:
    """Keyword pass over controls_fts (populated by build_vector_index.py):
    ID-like tokens from the query match the control_id column: tokens
    carrying a digit or separator match by prefix ("AC-2" also finds
    "AC-2(1)"), pure-alpha tokens of length 3+ match whole, and two-letter
    glue words are ignored. Every token is double-quoted with
    no spaces around the column colon (older SQLite FTS5 rejects
    `{col : ...}`), so user input can never raise; a missing controls_fts
    table (index built before R-106) degrades to no exact hits. Returns
    (rowid, control_id, framework, text) rows."""
    seen, tokens = set(), []
    for tok in _FTS_ID_TOKEN.findall(query or ""):
        # Two-letter glue words ("at", "of", "to") collide with ID fragments
        # ("PR.AT-1") - only longer pure-alpha tokens mint exact matches;
        # anything carrying a digit or separator (AC-2, CWE-79) always counts.
        if tok.isalpha() and len(tok) < 3:
            continue
        upper = tok.upper()
        if upper not in seen:
            seen.add(upper)
            tokens.append(tok)
    if not tokens:
        return []
    # Prefix (*) only on ID-shaped tokens (digit or separator: AC-2 finds
    # AC-2(1)); pure-alpha tokens match whole ("rest" must not prefix-match
    # "restrict_admin").
    def _clause(t):
        if any(c.isdigit() or c in ".-_()/" for c in t):
            return f'control_id:"{t}"*'
        return f'control_id:"{t}"'
    match = " OR ".join(_clause(t) for t in tokens)
    # Full-ID equality on the longest token outranks prefix siblings, so
    # "AC-2" beats "PR.AC-2"/"AC-2(1)" regardless of rowid order. Tokens
    # match [A-Za-z0-9._\-()/]+ (no quotes possible), so the CASE literal
    # cannot break out of its string.
    best = max(tokens, key=len).upper()
    sql = ("SELECT rowid, control_id, framework, text FROM controls_fts "
           "WHERE controls_fts MATCH ?")
    params: list = [match]
    if framework:
        sql += " AND framework = ?"
        params.append(framework)
    sql += f" ORDER BY CASE WHEN upper(control_id) = '{best}' THEN 0 ELSE 1 END, rowid LIMIT ?"
    params.append(limit)
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


# --------------------------------------------------------------------------
# Tools
# --------------------------------------------------------------------------

@server.tool()
def search_controls(query: str, framework: str | None = None, top_k: int = 10) -> dict:
    """Semantic search over all ~42,000 indexed controls. Use natural
    language, e.g. "encryption of data at rest" or "multi-factor
    authentication for privileged access". Optionally restrict to one
    framework prefix - call list_frameworks() first to get valid prefixes
    (e.g. "NIST53", "CSF2", "ATTACK", "FEDRAMP20X", "PCIDSS_4").

    Match quality varies by family: NIST53/NIST171/CSF2/ASVS/ATTACK/FEDRAMP20X
    and every ComplianceAsCode-derived family (CIS/STIG/E8/HIPAA/PCIDSS/...)
    have real control descriptions and search well. The ~248 `SCF_*`-prefixed
    families (the Secure Controls Framework crosswalk's per-standard columns,
    e.g. SCF_GENERAL_ISO_27001_2022) index bare clause-number strings (e.g.
    "4.2 4.2(a)") as their "text", not real descriptions - semantic search
    over them is low-quality by construction (there's no real text to
    embed). For an SCF_* target, use crosswalk_control() instead - it joins
    through the SCF's own shared control-ID structure (deterministic, not
    similarity-based). get_control() also still works against an SCF_*
    family if you already know the exact SCF control ID. Returns the top_k
    best matches with a similarity distance (lower = closer). Hybrid
    retrieval: exact control-ID hits (match="exact", distance 0.0) lead, so
    asking for "AC-2" or "CWE-79" returns that control first - trust it and
    stop there instead of reading further; semantic neighbors follow with
    match="semantic"."""
    conn = _vector_conn()
    q = _embed_query(query)
    top_k = max(1, min(top_k, 50))
    # `framework` is a vec0 partition key (see build_vector_index.py) - filtering
    # on it here searches within that partition directly, not a post-hoc
    # filter over the unfiltered global top-k (which could miss true nearest
    # neighbors that fall outside that window).
    if framework:
        rows = conn.execute(
            """
            SELECT cm.control_id, cm.framework, cm.text, v.distance
            FROM controls_vec v JOIN controls_meta cm ON cm.rowid = v.rowid
            WHERE v.embedding MATCH ? AND v.framework = ? AND k = ?
            ORDER BY v.distance
            """,
            (q, framework, top_k),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT cm.control_id, cm.framework, cm.text, v.distance
            FROM controls_vec v JOIN controls_meta cm ON cm.rowid = v.rowid
            WHERE v.embedding MATCH ? AND k = ?
            ORDER BY v.distance
            """,
            (q, top_k),
        ).fetchall()
    # Exact keyword hits lead (match="exact") so an agent asking for "AC-2"
    # gets AC-2 first instead of burning context on near-misses; semantic
    # neighbors follow with match="semantic", deduplicated, capped at top_k.
    results, seen_keys = [], set()
    for _rowid, cid, fw, text in _fts_exact_matches(conn, query, framework, top_k):
        key = (fw, cid)
        if key not in seen_keys:
            seen_keys.add(key)
            results.append({"control_id": cid, "framework": fw, "text": text, "distance": 0.0, "match": "exact"})
    for r in rows:
        key = (r[1], r[0])
        if key not in seen_keys:
            seen_keys.add(key)
            results.append({"control_id": r[0], "framework": r[1], "text": r[2], "distance": round(r[3], 4), "match": "semantic"})
    return {
        "query": query,
        "results": results[:top_k],
    }


@server.tool()
def get_control(control_id: str, framework: str) -> dict:
    """Exact lookup of one control's text by its ID and framework prefix
    (e.g. framework="NIST53", control_id="AC-2"). Use list_frameworks() to
    find valid prefixes, or search_controls() first if you don't already
    know the exact ID. Note: SOC2's own CC-numbered criteria (CC6.1 etc.)
    aren't independently indexed - they only appear as crosswalk targets via
    crosswalk_rule(); use that for SOC2, not this."""
    conn = _vector_conn()
    row = conn.execute(
        "SELECT control_id, framework, text FROM controls_meta WHERE framework = ? AND control_id = ? LIMIT 1",
        (framework, control_id),
    ).fetchone()
    if row is None:
        return {"found": False, "control_id": control_id, "framework": framework}
    return {"found": True, "control_id": row[0], "framework": row[1], "text": row[2]}


@server.tool()
def list_frameworks() -> dict:
    """Lists every indexed framework family (prefix -> human-readable label)
    and its control count. ~300 entries covering SOC2, NIST, ISO, GDPR,
    HIPAA, PCI DSS, CIS, MITRE ATT&CK, FedRAMP 20x, and more."""
    with open(FRAMEWORK_METADATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    counts: dict[str, int] = {}
    for key in data.get("controls", {}):
        prefix = key.split(":", 1)[0]
        counts[prefix] = counts.get(prefix, 0) + 1
    return {
        "frameworks": [
            {"prefix": k, "label": v, "control_count": counts.get(k, 0)}
            for k, v in sorted(data.get("frameworks", {}).items())
        ]
    }


@server.tool()
def crosswalk_rule(rule_id: str) -> dict:
    """Looks up a native audit_repo.py rule ID (e.g. "SEC001", "IAM001") or an
    external scanner rule ID (Checkov/Semgrep) in framework_mappings.json's
    hand-authored crosswalk, returning every framework control it maps to
    (SOC2, NIST, HIPAA, AWS Well-Architected, MITRE ATT&CK, etc.)."""
    with open(FRAMEWORK_MAPPINGS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    mappings = data.get("mappings", {})
    hit = mappings.get(rule_id)
    if hit is None:
        return {"found": False, "rule_id": rule_id}
    return {"found": True, "rule_id": rule_id, "frameworks": hit}


@server.tool()
def crosswalk_control(control_id: str, framework: str, target_framework: str, top_k: int = 3) -> dict:
    """Crosswalk one control from `framework` to its equivalent(s) in
    `target_framework`. Uses the most trustworthy method available for the
    pair, reported in the result's "method" field:

    - "exact_scf_direct": both frameworks are `SCF_*` families (Secure
      Controls Framework crosswalk columns, e.g. SCF_GENERAL_ISO_27001_2022)
      - they share the same underlying SCF control ID, so this is a direct,
      exact lookup. Trustworthy.
    - "exact_scf_token_join" (R-047): target_framework is `SCF_*` but the
      source isn't. Looks up control_id as a literal token across every
      SCF_* family's clause values to find its SCF control ID, then reads
      target_framework's clause for that same ID. Deterministic (a token
      either matches or it doesn't) and far more reliable than similarity
      search over SCF_*'s bare clause-number text - but still a token match,
      not a certified legal mapping; verify before citing.
    - "semantic_similarity": target_framework has real descriptive control
      text (NIST53/NIST171/CSF2/ASVS/ATTACK/FEDRAMP20X/ComplianceAsCode
      families). Nearest-neighbor embedding similarity - a starting point
      for manual verification, never a citation on its own.
    """
    got = get_control(control_id, framework)
    if not got["found"]:
        return {"found": False, "reason": f"{framework}:{control_id} not indexed"}

    if framework.startswith("SCF_") and target_framework.startswith("SCF_"):
        target = get_control(control_id, target_framework)
        return {
            "found": True, "method": "exact_scf_direct",
            "source": {"framework": framework, "control_id": control_id, "text": got["text"]},
            "candidates": ([{"control_id": target["control_id"], "text": target["text"], "distance": 0.0}]
                           if target["found"] else []),
        }

    if target_framework.startswith("SCF_"):
        conn = _vector_conn()
        token = control_id.strip().upper()
        hits = conn.execute(
            "SELECT DISTINCT scf_family, scf_id FROM scf_crosswalk_tokens WHERE token = ?",
            (token,),
        ).fetchall()
        candidates = []
        for scf_family, scf_id in hits:
            row = conn.execute(
                "SELECT text FROM controls_meta WHERE framework = ? AND control_id = ?",
                (target_framework, scf_id),
            ).fetchone()
            if row:
                candidates.append({
                    "control_id": scf_id, "text": row[0], "distance": 0.0,
                    "matched_via": scf_family,  # which SCF family's column contained this token - sanity-check against source
                })
        return {
            "found": True, "method": "exact_scf_token_join",
            "source": {"framework": framework, "control_id": control_id, "text": got["text"]},
            "candidates": candidates[:max(1, min(top_k, 20))],
        }

    conn = _vector_conn()
    q = _embed_query(got["text"])
    top_k = max(1, min(top_k, 20))
    rows = conn.execute(
        """
        SELECT cm.control_id, cm.text, v.distance
        FROM controls_vec v JOIN controls_meta cm ON cm.rowid = v.rowid
        WHERE v.embedding MATCH ? AND v.framework = ? AND k = ?
        ORDER BY v.distance
        """,
        (q, target_framework, top_k),
    ).fetchall()
    return {
        "found": True, "method": "semantic_similarity",
        "source": {"framework": framework, "control_id": control_id, "text": got["text"]},
        "candidates": [
            {"control_id": r[0], "text": r[1], "distance": round(r[2], 4)} for r in rows
        ],
    }


@server.tool()
def search_documents(query: str, top_k: int = 5) -> dict:
    """Semantic search over cached full text of the ~300 tracked standards
    themselves (not the parsed controls - the actual document prose, where
    cached). Falls back to name/publisher for documents not yet cached. Use
    get_document() for a specific document's metadata/cache status."""
    conn = _vector_conn()
    q = _embed_query(query)
    top_k = max(1, min(top_k, 20))
    rows = conn.execute(
        """
        SELECT dm.fdi, dm.chunk_index, dm.source, dm.text, v.distance
        FROM documents_vec v JOIN documents_meta dm ON dm.rowid = v.rowid
        WHERE v.embedding MATCH ? AND k = ?
        ORDER BY v.distance
        """,
        (q, top_k),
    ).fetchall()
    return {
        "query": query,
        "results": [
            {"fdi": r[0], "chunk_index": r[1], "source": r[2], "text": r[3], "distance": round(r[4], 4)}
            for r in rows
        ],
    }


@server.tool()
def get_document(fdi: str) -> dict:
    """Metadata for one tracked standard by its Focal Document Identifier
    (FDI) - real name, issuing body, official source URL, redistribution-
    rights classification, and whether/where its full text is cached
    locally. Use search_documents() or list_frameworks() to discover FDIs."""
    conn = sqlite3.connect(str(DOCUMENT_CATALOG_PATH))
    row = conn.execute(
        "SELECT fdi, name, issuing_body, geography, source_url, license_status, "
        "license_note, full_text_cached, cached_path FROM documents WHERE fdi = ?",
        (fdi,),
    ).fetchone()
    conn.close()
    if row is None:
        return {"found": False, "fdi": fdi}
    return {
        "found": True, "fdi": row[0], "name": row[1], "issuing_body": row[2],
        "geography": row[3], "source_url": row[4], "license_status": row[5],
        "license_note": row[6], "full_text_cached": bool(row[7]), "cached_path": row[8],
    }


@server.tool()
def run_audit(path: str, fail_on: str | None = None, min_severity: str | None = None) -> dict:
    """Runs the audit_repo.py static compliance scanner (the CLAUDE.md
    Review Loop's mandated check) against a directory and returns the
    findings as structured JSON, each tagged with its SOC2/crosswalk
    controls. `path` is relative to the AuditForge repo root or absolute.
    `fail_on`/`min_severity` are optional severity filters (LOW/MEDIUM/HIGH/CRITICAL)."""
    target = (ROOT / path) if not os.path.isabs(path) else Path(path)
    cmd = [sys.executable, str(AUDIT_REPO_PATH), str(target), "--json"]
    if fail_on:
        cmd += ["--fail-on", fail_on]
    if min_severity:
        cmd += ["--min-severity", min_severity]
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT), timeout=120)
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "non-JSON output from audit_repo.py", "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:], "returncode": result.returncode}
    payload["returncode"] = result.returncode
    return payload


@server.tool()
def run_universal_audit(path: str, engines: list | None = None,
                        timeout_s: int = 600, no_cache: bool = False) -> dict:
    """Runs the full multi-engine pipeline (Checkov, Semgrep, Trivy, OSV,
    cargo-audit, Nuclei, Scorecard, TruffleHog, SBOM, DAST, email auth,
    cloud posture) against a directory and returns the unified JSON report:
    normalized findings with cross-framework controls, engine availability,
    engine errors, and an honest run_status (complete/partial + reason).
    `path` is relative to the AuditForge repo root or absolute. `engines`
    optionally subsets the pipeline (e.g. ["semgrep","osv","trivy"] for a
    fast SAST+SCA pass); missing binaries skip gracefully and are reported
    under engine_availability rather than failing the run."""
    target = (ROOT / path) if not os.path.isabs(path) else Path(path)
    cmd = [sys.executable, str(ROOT / "scripts" / "universal_audit.py"),
           str(target), "--format", "json"]
    if engines:
        cmd += ["--engines", ",".join(engines)]
    if no_cache:
        cmd += ["--no-cache"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"error": f"universal audit timed out after {timeout_s}s",
                "engines": engines or "all"}
    if len(result.stdout) > 10 * 1024 * 1024:
        return {"error": "universal audit output exceeded 10 MiB cap",
                "stderr": result.stderr[-2000:], "returncode": result.returncode}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "non-JSON output from universal_audit.py",
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:], "returncode": result.returncode}
    payload["returncode"] = result.returncode
    return payload


@server.tool()
def engine_status() -> dict:
    """Which external scanner binaries are on PATH right now (Checkov,
    Semgrep, Trivy, cargo-audit, Nuclei, Scorecard, TruffleHog). A missing
    tool means its engines skip gracefully - reported here and in every
    universal report's engine_availability, never a silent zero-findings
    claim. Install hints live in config/compliance_config.yaml."""
    from auditor import scanners
    return {"engines": scanners.engine_availability()}



@server.tool()
def audit_policy_docs(path: str, top_k: int = 2) -> dict:
    """Audits which governance/policy documents a repo actually has.
    Checks the 15-policy required catalog (access control, incident
    response, encryption, logging, change/vendor/risk management, ...)
    against the target\'s docs by filename and content keywords, with
    live NIST 800-53 / CSF / SOC2-TSC citations per policy. Returns
    present/partial/missing-must/should-consider per policy plus an
    unresolved_refs list. `path` is relative to the AuditForge repo
    root or absolute. Point it at the org\'s policy folder for a clean
    signal, or a whole repo for a corpus-wide sweep."""
    target = (ROOT / path) if not os.path.isabs(path) else Path(path)
    cmd = [sys.executable, str(ROOT / "scripts" / "policy_audit.py"),
           str(target), "--top-k", str(top_k)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "policy audit timed out after 300s"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "non-JSON output from policy_audit.py",
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:],
                "returncode": result.returncode}
    payload["returncode"] = result.returncode
    return payload


@server.tool()
def run_gap_analysis(path: str, domain: str = "auto",
                     top_k: int = 2) -> dict:
    """Diffs what a codebase SHOULD have against what it has: 12 domain
    profiles (website, api-service, mcp-server, llm-app, cli-tool,
    library-sdk, iac-cloud, kubernetes, ci-pipeline, mobile-app,
    desktop-app, data-pipeline) with must-build gaps, present
    capabilities, and live framework citations. `domain="auto"` picks
    the best-fitting profile. `path` is relative to the AuditForge
    repo root or absolute."""
    target = (ROOT / path) if not os.path.isabs(path) else Path(path)
    cmd = [sys.executable, str(ROOT / "scripts" / "gap_analysis.py"),
           str(target), "--domain", domain, "--top-k", str(top_k)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "gap analysis timed out after 300s"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "non-JSON output from gap_analysis.py",
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:],
                "returncode": result.returncode}
    payload["returncode"] = result.returncode
    return payload


@server.tool()
def ledger_stats(repo: str = ".") -> dict:
    """Finding-lifecycle ledger summary for a repo: recorded runs,
    findings by status, and top open rules. Read-only (stats never
    mutates the ledger). `repo` is relative to the AuditForge root or
    absolute; the ledger DB stays next to the scanned repo."""
    target = (ROOT / repo) if not os.path.isabs(repo) else Path(repo)
    cmd = [sys.executable, str(ROOT / "scripts" / "ledger.py"),
           "stats", "--repo", str(target)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "ledger stats timed out after 120s"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "non-JSON output from ledger.py",
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:],
                "returncode": result.returncode}
    payload["returncode"] = result.returncode
    return payload


@server.tool()
def validate_findings_report(path: str) -> dict:
    """Validates a findings JSON file against report-schema.json
    (required fields, severity vocabulary, control-ref shape). Returns
    the validator\'s returncode plus its stdout/stderr - returncode 0
    means the file is schema-clean. `path` is relative to the
    AuditForge repo root or absolute."""
    target = (ROOT / path) if not os.path.isabs(path) else Path(path)
    cmd = [sys.executable, str(ROOT / "scripts" / "validate_findings.py"),
           str(target)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "validate_findings timed out after 120s"}
    return {"returncode": result.returncode,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-2000:]}


@server.tool()
def validate_coverage_ledger_report(path: str) -> dict:
    """Validates a coverage-ledger JSON file (every claimed control
    maps to a real framework control, no orphan entries). Returns the
    validator\'s returncode plus its stdout/stderr - returncode 0 means
    clean. `path` is relative to the AuditForge repo root or absolute."""
    target = (ROOT / path) if not os.path.isabs(path) else Path(path)
    cmd = [sys.executable,
           str(ROOT / "scripts" / "validate_coverage_ledger.py"),
           str(target)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "validate_coverage_ledger timed out after 120s"}
    return {"returncode": result.returncode,
            "stdout": result.stdout[-4000:],
            "stderr": result.stderr[-2000:]}


@server.tool()
def check_freshness(skip_kev: bool = True) -> dict:
    """Diffs the live knowledge stack (framework metadata counts, KEV
    catalog, OSV reachability) against scripts/freshness_manifest.json.
    Read-only - it never rewrites the baseline (refresh via
    `python scripts/check_freshness.py --write` on the shell).
    `skip_kev` avoids the CISA network fetch for offline runs."""
    cmd = [sys.executable, str(ROOT / "scripts" / "check_freshness.py")]
    if skip_kev:
        cmd += ["--skip-kev"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                cwd=str(ROOT), timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "freshness check timed out after 300s"}
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"returncode": result.returncode,
                "stdout": result.stdout[-4000:],
                "stderr": result.stderr[-2000:]}
    payload["returncode"] = result.returncode
    return payload


@server.tool()
def kev_lookup(cve_id: str) -> dict:
    """Checks CISA's Known Exploited Vulnerabilities (KEV) catalog for one
    CVE - free, no API key. Returns whether it's confirmed actively
    exploited in the wild, plus remediation deadline and ransomware-use
    flag if so. Use this to prioritize dependency-scan findings by real-world
    urgency, not just CVSS severity."""
    hit = vuln_intel.check_kev(cve_id)
    return {"cve": cve_id.upper(), "known_exploited": hit is not None, "detail": hit}


@server.tool()
def epss_lookup(cve_ids: list[str]) -> dict:
    """FIRST.org EPSS scores (free, no API key) for up to 100 CVEs at once -
    the daily-updated probability (0-1) each will be exploited in the next
    30 days. Use alongside kev_lookup() for risk-based remediation
    prioritization (SOC2 CC7.1/CC7.2)."""
    return vuln_intel.get_epss(cve_ids)


@server.tool()
def nvd_lookup(cve_id: str) -> dict:
    """CVE detail (CVSS vector/score, description, references) from NIST's
    NVD API 2.0 - free, no API key required (set NVD_API_KEY env var for a
    higher rate limit, still free)."""
    detail = vuln_intel.get_nvd_detail(cve_id)
    return {"cve": cve_id.upper(), "found": detail is not None, "detail": detail}


if __name__ == "__main__":
    server.run()
