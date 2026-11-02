# AuditForge plugin (native Muse package)

Distributable wrapper around this repo: two skills, two commands, and the
control-search MCP server. Installs elsewhere with:

```json
{
  "program": "muse",
  "argv": ["plugins", "install", "<canonical-plugin-path>"],
  "executed": false
}
```

(Installation is intentionally never run from here.)

## Layout

- `.muse-plugin/plugin.json` - manifest (skills + commands + mcpServers).
- `.claude-plugin/plugin.json` - skeleton Claude Code manifest (same skills +
  commands; extend when the marketplace repo location is decided - see
  `docs/current/tooling-direction.md` §5).
- `../../.claude-plugin/marketplace.json` - skeleton marketplace index
  pointing at this plugin directory.
- `skills/auditforge/SKILL.md`, `skills/security-audit/SKILL.md` - plugin
  copies; canonical sources live in `.claude/skills/` - reconcile on bump.
- `commands/audit.md` - full-sweep audit (default) with a fast-subset flag.
- `commands/freshness.md` - freshness gate + baseline flow.
- `mcp/server.py` - launcher: resolves the checkout from `AUDITFORGE_HOME`
  and execs its project-local interpreter (never a global Python).

Set `AUDITFORGE_HOME` to the repo root before the MCP client spawns the
bundled server. The knowledge-base clones stay in the checkout (they are
gitignored reference material, not plugin weight).
