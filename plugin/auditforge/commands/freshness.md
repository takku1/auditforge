---
description: Check the AuditForge knowledge stack for silent rot and record a new baseline
argument-hint: [--write]
---

Freshness gate for the knowledge stack (family counts, KB commits, engine
versions, KEV IDs, index staleness, calendar watches):

1. `python scripts/check_freshness.py` - compare live state against the
   tracked baseline (`scripts/freshness_manifest.json`). Exit 1 on
   regression (vanished/zeroed/shrunk families); new KEV IDs print as
   WATCH triage items, never failures.
2. If the gate passes and the drift is legitimate upstream change:
   `python scripts/check_freshness.py --write` records the new baseline.
3. Commit `scripts/freshness_manifest.json` (+ `framework_metadata.json`
   if regenerated). Never hand-edit either.

Run `python scripts/update_engines.py` first when template/DB refreshes
(Nuclei, Trivy) are due - it is best-effort and never fails the gate.
