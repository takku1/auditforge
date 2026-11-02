#!/usr/bin/env python3
"""AuditForge MCP server launcher (plugin-relative entry point).

Resolves the AuditForge checkout from the AUDITFORGE_HOME environment
variable and execs its project-local interpreter against
scripts/mcp_server.py - dependencies live in the checkout's .venv, never
in a global Python. Set AUDITFORGE_HOME to the repo root before the MCP
client spawns this server:

  Windows:     set AUDITFORGE_HOME=Z:\\auditforge
  macOS/Linux: export AUDITFORGE_HOME=/path/to/auditforge
"""

import os
import sys


def main() -> int:
    home = os.environ.get("AUDITFORGE_HOME", "").strip()
    if not home:
        sys.stderr.write(
            "auditforge: AUDITFORGE_HOME is not set - point it at the "
            "AuditForge checkout (repo root) and retry.\n")
        return 2
    if os.name == "nt":
        python = os.path.join(home, ".venv", "Scripts", "python.exe")
    else:
        python = os.path.join(home, ".venv", "bin", "python")
    server = os.path.join(home, "scripts", "mcp_server.py")
    for path, label in ((python, "interpreter"), (server, "mcp_server.py")):
        if not os.path.isfile(path):
            sys.stderr.write(
                f"auditforge: {label} not found at {path} - check "
                "AUDITFORGE_HOME and the checkout's .venv setup.\n")
            return 2
    os.execv(python, [python, server])
    return 0  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
