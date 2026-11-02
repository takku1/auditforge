# Attack-class category pack (vendored)

Source: Cloudflare `security-audit-skill`
(`github.com/cloudflare/security-audit-skill`), MIT License,
Copyright (c) 2025-2026 Cloudflare, Inc. — see `resources/`
reference clone (gitignored) or the upstream repo for the full text
and history. Files here are byte-identical copies, vendored
2026-11-02 so AuditForge's security-audit skill is self-contained.

MIT permission notice (upstream LICENSE):

> Permission is hereby granted, free of charge, to any person obtaining
> a copy of this software and associated documentation files (the
> "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish,
> distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject
> to the following conditions:
>
> The above copyright notice and this permission notice shall be
> included in all copies or substantial portions of the Software.

What these are: the hunting taxonomy for the security-audit skill —
`ATTACK-CLASSES.md` (router) + 10 `When to use`-gated companion packs
(AI, client-side, cloud, data isolation, desktop/mobile, memory safety,
protocols/RPC, resource exhaustion, supply chain, web protocols/auth)
plus `HUNTING.md`, `RECONNAISSANCE.md`, `VALIDATION-AND-REPORTING.md`
(method). AuditForge additions live elsewhere, not in these files:
deterministic Phase-0 sweep, compliance citations, Python validators,
`reports/` output convention — see
`.claude/skills/security-audit/SKILL.md`.
