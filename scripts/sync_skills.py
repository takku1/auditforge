"""Regenerate plugin skill copies from canonical sources.

The `.claude/skills/<id>/SKILL.md` files are canonical. The distributable
plugin carries copies with a provenance callout after the title. Regenerate
with `python scripts/sync_skills.py`; CI enforces freshness through
`test_skill_copies_in_sync` in `scripts/test_validate_audit_skill.py`
(use `--check` for an explicit gate).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

SKILLS = ("auditforge", "security-audit")


def render(skill: str, canonical: str) -> str:
    """Insert the provenance callout after the first `# ` title line."""
    callout = textwrap.fill(
        "Plugin copy. Canonical source: `.claude/skills/%s/SKILL.md` in "
        "the AuditForge repo - reconcile on bump (same pin-and-reconcile "
        "habit as `resources/`)." % skill,
        width=76, subsequent_indent="> ",
        initial_indent="> ", break_long_words=False,
        break_on_hyphens=False)
    lines = canonical.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("# "):
            after = lines[i + 1:]
            while after and not after[0].strip():
                after = after[1:]
            return "\n".join(lines[:i + 1] + ["", callout, ""] +
                             after).lstrip("\n")
    raise ValueError("no '# ' title line in canonical skill %s" % skill)


def main(argv: list[str] | None = None) -> int:
    check_only = (argv or ["--write"])[0] == "--check"
    root = Path(__file__).resolve().parent.parent
    dirty = []
    for skill in SKILLS:
        canon = root / ".claude" / "skills" / skill / "SKILL.md"
        copy = root / "plugin" / "auditforge" / "skills" / skill / "SKILL.md"
        want = render(skill, canon.read_text(encoding="utf-8"))
        if copy.read_text(encoding="utf-8") != want:
            if check_only:
                dirty.append(skill)
            else:
                copy.write_text(want, encoding="utf-8", newline="\n")
                print("synced %s" % copy)
    if check_only and dirty:
        print("out of sync (run: python scripts/sync_skills.py): %s"
              % ", ".join(dirty))
        return 1
    if check_only:
        print("skill copies in sync")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
