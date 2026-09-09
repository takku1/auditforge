# Agentic Layer (L1)

<!-- recurspec-contract: 1.0 -->

## 1. System Intent & Responsibility

Exposes [framework-sync](../framework-sync/SYSTEM.md)'s derived knowledge
base to an AI agent as fast, scoped, typed tools instead of requiring an
agent to shell out to CLIs and parse text: an MCP server
(`mcp_server.py`), a local sqlite-vec semantic index builder
(`build_vector_index.py`), and a free vulnerability-intelligence client
(`vuln_intel.py`, also consumed by
[auditor-core](../auditor-core/SYSTEM.md)'s OSV scan path).

Does not own: the underlying control/document data (framework-sync's), the
static-scanning detection logic (`run_audit()` is a thin subprocess wrapper
around `audit_repo.py`, not a reimplementation).

## 2. Sub-System Decomposition

Atomic leaf (BUILD — new, added 2026-09-09 in direct response to a request
to build an agentic layer over the existing knowledge base).

## 3. Interface Contracts

- **Inputs:** `scripts/framework_metadata.json`, `scripts/document_catalog.db`, `scripts/document_cache/` (from framework-sync); MCP stdio protocol requests; free-API responses (CISA KEV, FIRST.org EPSS, NVD).
- **Outputs:** `scripts/vector_index.db` (derived, gitignored - too large for git, regenerable in ~14 minutes); MCP tool call results (small, scoped JSON); `scripts/vuln_intel_cache.db` (derived, gitignored, TTL'd).

## 4. Invariants (EARS + Epistemic Stage)

- **[Ubiquitous]** THE SYSTEM SHALL answer a control search without loading
  the full `scripts/framework_metadata.json` into the calling agent's context -
  retrieval happens inside `mcp_server.py`, only top-k scoped results cross
  back to the model (live-verified `search_controls()` latency and result
  shape against the real 42k+-row index).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL restrict a framework-filtered search to
  that framework's vec0 partition, not filter an unfiltered top-k
  after the fact (`test_search_controls_framework_filter_uses_partition_key`).
  - `EvidenceStage:` Sampled
- **[Conditional]** IF a crosswalk's target framework is one of the
  `SCF_*` families THEN THE SYSTEM SHALL join through the shared SCF
  control-ID token index (exact match) instead of embedding similarity
  (R-047; `test_crosswalk_control_exact_scf_token_join`).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL query CISA KEV/EPSS/NVD without any
  required API key, and cache responses locally to respect rate limits
  (live-verified against real APIs; TTL/staleness logic under test in
  `test_vuln_intel.py`).
  - `EvidenceStage:` Sampled
- **[Ubiquitous]** THE SYSTEM SHALL install its dependencies (`mcp`,
  `sentence-transformers`, `sqlite-vec`, `pypdf`) only into a project-local
  `.venv/`, never a global/system Python (this session broke, then fixed,
  exactly this by installing into the global env first - see ROADMAP R-045).
  - `EvidenceStage:` Observed

## 5. Architectural Decisions (ADRs)

- **ADR-141:** sqlite-vec over a server-shaped vector DB (Chroma/Qdrant) —
  matches the project's existing dependency-free, single-file ethos
  (`audit_repo.py`); no service to start, a query is one indexed `SELECT`.
- **ADR-142:** `BAAI/bge-small-en-v1.5` (local CPU embeddings) over an API
  embedding service — zero marginal cost per query, no external dependency
  for a tool meant to run offline-capable; asymmetric query/passage
  convention (`Represent this sentence for searching relevant passages: `
  prefix on queries only) is bge's documented usage, not invented here.
- **ADR-143 (R-047):** `framework`/`fdi` are vec0 *partition keys*, not
  post-query filters — chosen after finding the naive filter-after-top-k
  approach would silently drop true nearest neighbors outside the
  unfiltered top-k window.
- **ADR-144 (R-047):** SCF-target crosswalk uses an exact token-join through
  `scf_crosswalk_tokens`, not embedding similarity — found via live testing
  that SCF_* families' indexed "text" is bare clause numbers (e.g.
  `"4.2 4.2(a)"`), which embed to near-meaningless vectors; the SCF
  crosswalk's own shared control-ID structure is a deterministic join key
  that already existed in the data and needed no similarity search at all.
- **ADR-145:** `HF_HUB_OFFLINE=1` set by default in `mcp_server.py`'s model
  loader (not `build_vector_index.py`'s, which needs network on first
  download) - cut cold `search_controls()` latency from ~45s to ~8s and
  removed HTTP logging noise from a process whose stdout carries the MCP
  JSON-RPC stream.

## 6. Leaf Execution & Test Seam

- **Implementation Files:** `scripts/mcp_server.py`,
  `scripts/build_vector_index.py`, `scripts/vuln_intel.py`,
  `scripts/test_mcp_server.py`, `scripts/test_build_vector_index.py`,
  `scripts/test_vuln_intel.py` (test files listed here too - see
  auditor-core's note on why Test Surface Seam alone isn't sufficient)
- **Test Surface Seam:** `scripts/test_mcp_server.py`, `scripts/test_build_vector_index.py`, `scripts/test_vuln_intel.py` (run via `python -m pytest`)

## 7. Measurement Seams

- **Primary Metric:** `pytest_pass_rate` (target: 1.0; direction: higher).
  No numeric retrieval-quality metric (e.g. recall@k) exists yet - stated
  honestly as absent rather than invented; `search_controls()`'s
  per-family quality difference (real descriptions vs. SCF_* clause
  numbers) is currently judged qualitatively (see ROADMAP R-047's
  before/after distance figures: ~0.45-0.68 vs. ~0.89).
- **Evaluation Gate:** `python -m pytest scripts/test_mcp_server.py
  scripts/test_build_vector_index.py scripts/test_vuln_intel.py` (exit 0)
- **Correctness Backpressure:** manual live smoke test against the real
  ~42k-control index (`search_controls`/`get_control`/`crosswalk_control`
  called directly, output eyeballed) - this is how R-047 itself was found;
  the fixture-based unit tests alone would not have caught it.
- **Telemetry Surface:** none.
- **Branching Policy:** n/a — direct commits to `main`.

## 8. Technology Resolution

- **Decision class:** BUILD
- **Justification:** no off-the-shelf product answers "MCP server over this
  project's specific 42k-control derived index with this specific
  crosswalk data" - the retrieval logic and crosswalk semantics are
  entirely project-specific.
- **Selected:** official `mcp` Python SDK (v2, `MCPServer`/stdio transport),
  `sqlite-vec`, `sentence-transformers`.
- **Standard / protocol:** Model Context Protocol (2026-07-28 spec, per the
  installed SDK version).
- **Alternatives considered:**
  | Option | Why not |
  | --- | --- |
  | chromadb (already installed on this machine) | heavier dependency footprint (onnxruntime, fastapi, telemetry) inconsistent with the project's dependency-free ethos; sqlite-vec sits directly beside the existing SQLite-first convention (`scripts/document_catalog.db`) |
  | nomic-embed-text / Qwen3-Embedding via Ollama | adds an Ollama daemon dependency; bge-small via sentence-transformers needed no new runtime |
- **Fit gap:** SCF_*-family semantic search remains low-quality where no
  token-join path applies (source framework not independently indexed
  anywhere in the crosswalk) - documented in tool docstrings, not hidden.
- **Seam:** `mcp_server.py`'s `@server.tool()`-decorated functions;
  `build_vector_index.build()`'s return dict.
- **Exit cost:** MEDIUM — ~900 lines across 3 files; the vec0 schema
  (partition keys, SCF token table) would need re-deriving if the vector
  store were swapped.
- **Cost model:** $0 marginal (local compute only; CISA KEV/EPSS/NVD are
  free with no usage cost).
- **Liability transferred:** none.
- **Operational owner:** us.
- **Failure mode:** `scripts/vector_index.db` missing/stale (not rebuilt after a
  `scripts/framework_metadata.json` update) silently serves outdated search results
  - no staleness check exists yet; `build_info.built_at` is recorded but not
  compared against the source files' mtimes anywhere.
- **Open questions:** should `mcp_server.py` warn when `scripts/vector_index.db` is
  older than `scripts/framework_metadata.json`/`scripts/document_catalog.db`? Not built -
  noting it here rather than pretending the gap doesn't exist.
