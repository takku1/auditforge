#!/usr/bin/env python3
"""Sandboxed PoC execution boundary (ROADMAP R-138).

Runs an untrusted proof-of-concept command inside a disposable, isolated
container and captures its artifacts. Refuses to run when no backend is
available - the caller must record needs_validation instead (a missing
sandbox never yields a confirmation).

Hardening invariants (all enforced by construction, asserted in
scripts/test_poc_sandbox.py::test_hardened_flags):
  - `--network none`: the PoC cannot reach the network, period.
  - Resource cage: `--cpus 1.0 --memory 256m --memory-swap 256m
    --pids-limit 64` - fork bombs and miners hit the ceiling fast.
  - `--cap-drop ALL` + `--security-opt no-new-privileges:true`: no
    privilege escalation inside the container.
  - `--read-only` rootfs + one `rw,noexec,nosuid` tmpfs: no persistence,
    no executable drops outside the artifact dir.
  - Exactly two mounts: the target workdir read-only at /work, the
    operator-owned artifact dir read-write at /out. The Docker socket,
    host home directories, cloud credential paths, and host env vars
    NEVER cross the boundary (only a fixed minimal PATH/HOME/USER).
  - `--pull never` + a pre-flight `image inspect`: images are
    operator-provisioned (`docker pull <image>` first); a run never
    fetches code at PoC time.
  - `--rm` + a unique `--name`: nothing survives the run; timeouts are
    followed by `docker rm -f` so a hung PoC cannot linger.
  - `--record` only ever records needs_validation (fail-closed). A
    confirmed verdict is always a separate, human/agent-reviewed
    `ledger.py verdict` command with the artifact as --evidence.

Backend resolution: `AUDITFORGE_DOCKER` env (a command line, e.g.
"<python> <stub>" in tests) or `docker` on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

REFUSAL_EXIT = 4

DEFAULT_IMAGE = "python:3.12-slim"
DEFAULT_TIMEOUT = 120


class PocRefused(Exception):
    """No safe execution backend: the PoC must NOT run."""

    def __init__(self, blocker: str):
        super().__init__(blocker)
        self.blocker = blocker


def _docker_base() -> list[str]:
    # posix=False on Windows: backslash paths (C:\...) must survive intact.
    return shlex.split(os.environ.get("AUDITFORGE_DOCKER", "docker"),
                       posix=os.name != "nt")


def backend_available() -> tuple[bool, str]:
    """(True, detail) when a docker daemon answers, else (False, blocker)."""
    base = _docker_base()
    if shutil.which(base[0]) is None:
        return False, "no docker backend on PATH (AUDITFORGE_DOCKER=%s)" % (
            os.environ.get("AUDITFORGE_DOCKER", "docker"))
    try:
        proc = subprocess.run(base + ["info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "docker info failed: %s" % exc
    if proc.returncode != 0:
        return False, ("docker daemon unreachable: %s"
                       % (proc.stderr.strip() or proc.stdout.strip()
                          or "exit %d" % proc.returncode))
    return True, "docker server %s" % (proc.stdout.strip() or "unknown")


def _image_present(base: list[str], image: str) -> bool:
    try:
        proc = subprocess.run(base + ["image", "inspect", image],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def _hardened_argv(base: list[str], name: str, cmd: list[str], workdir: str,
                   image: str, outdir: str) -> list[str]:
    return base + [
        "run", "--rm", "--name", name,
        "--network", "none",
        "--cpus", "1.0", "--memory", "256m", "--memory-swap", "256m",
        "--pids-limit", "64",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
        "--pull", "never",
        "--user", "65534:65534",
        "-e", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "-e", "HOME=/tmp",
        "-e", "USER=poc",
        "-v", "%s:/work:ro" % workdir,
        "-v", "%s:/out:rw" % outdir,
        "-w", "/work",
        image,
    ] + cmd


def run_poc(cmd: list[str], workdir: str, image: str = DEFAULT_IMAGE,
            timeout: int = DEFAULT_TIMEOUT, outdir: str = "") -> dict:
    """Execute cmd in a disposable hardened container. Raises PocRefused
    when no backend (or image) is available; never runs unprotected."""
    if not cmd:
        raise PocRefused("empty PoC command: nothing to run")
    if not os.path.isdir(workdir):
        raise PocRefused("workdir is not a directory: %s" % workdir)
    ok, detail = backend_available()
    if not ok:
        raise PocRefused(detail)
    base = _docker_base()
    if not _image_present(base, image):
        raise PocRefused("image not present locally: %s "
                         "(pre-pull with `docker pull %s`; "
                         "runs never fetch images)" % (image, image))
    out = outdir or os.path.join(workdir, ".poc-out")
    os.makedirs(out, exist_ok=True)
    name = "auditforge-poc-%s" % uuid.uuid4().hex[:12]
    argv = _hardened_argv(base, name, cmd, os.path.abspath(workdir),
                          image, os.path.abspath(out))
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(base + ["rm", "-f", name],
                       capture_output=True, timeout=30)
        return {"status": "timeout", "verdict": "needs_validation",
                "blocker": "PoC exceeded %ds; container %s removed" % (
                    timeout, name),
                "stdout_tail": (exc.stdout or b"").decode(
                    "utf-8", "replace")[-2000:] if exc.stdout else "",
                "stderr_tail": (exc.stderr or b"").decode(
                    "utf-8", "replace")[-2000:] if exc.stderr else "",
                "artifacts": [], "container": name}
    artifacts = sorted(p.name for p in Path(out).iterdir())
    status = "completed" if proc.returncode == 0 else "error"
    result = {"status": status,
              "returncode": proc.returncode,
              "stdout_tail": proc.stdout[-2000:],
              "stderr_tail": proc.stderr[-2000:],
              "artifacts": artifacts,
              "outdir": os.path.abspath(out),
              "container": name}
    if status != "completed":
        result["verdict"] = "needs_validation"
        result["blocker"] = ("PoC exited %d; treat as inconclusive, "
                             "not as disproof" % proc.returncode)
    return result


def _refusal_payload(blocker: str) -> dict:
    return {"status": "refused", "verdict": "needs_validation",
            "blocker": blocker}


def cmd_run(args) -> int:
    try:
        result = run_poc(shlex.split(args.cmd), args.workdir, args.image,
                         args.timeout, args.outdir)
    except PocRefused as exc:
        payload = _refusal_payload(exc.blocker)
        print(json.dumps(payload))
        if args.record:
            rec = _record_with(args, exc.blocker)
            return REFUSAL_EXIT if rec == 0 else rec
        return REFUSAL_EXIT
    print(json.dumps(result, indent=2))
    if args.record and result.get("status") != "completed":
        return _record_with(args, result.get("blocker", "PoC inconclusive"))
    if args.record and result.get("status") == "completed":
        print(json.dumps({"record": "skipped",
                          "reason": "completed PoCs are never auto-confirmed; "
                                    "review the artifacts, then record "
                                    "`ledger.py verdict --verdict confirmed "
                                    "--evidence <artifact> with an "
                                    "independent --verifier"}))
    return 0


def _record_with(args, blocker: str) -> int:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ledger
    return ledger.main(["--db", args.db, "verdict", "--repo", args.repo,
                        "--fingerprint", args.fingerprint,
                        "--verdict", "needs_validation",
                        "--run-id", args.run_id, "--reason", blocker,
                        "--verifier", args.verifier])


def cmd_check(_args) -> int:
    ok, detail = backend_available()
    print(json.dumps({"available": ok, "detail": detail}))
    return 0 if ok else REFUSAL_EXIT


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Sandboxed PoC execution boundary (R-138).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="Probe backend availability")
    c.set_defaults(fn=cmd_check)
    r = sub.add_parser("run", help="Run a PoC command in a hardened container")
    r.add_argument("--cmd", required=True,
                   help="command line to execute inside the container")
    r.add_argument("--workdir", required=True,
                   help="target checkout, mounted read-only at /work")
    r.add_argument("--image", default=DEFAULT_IMAGE)
    r.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    r.add_argument("--outdir", default="",
                   help="artifact dir, mounted read-write at /out")
    r.add_argument("--record", action="store_true",
                   help="on refusal/inconclusive runs, record "
                        "needs_validation to the ledger (never confirms)")
    r.add_argument("--repo", default="")
    r.add_argument("--fingerprint", default="")
    r.add_argument("--run-id", default="")
    r.add_argument("--db", default="")
    r.add_argument("--verifier", default="",
                   help="identity recorded on the needs_validation verdict")
    r.set_defaults(fn=cmd_run)
    args = parser.parse_args(argv)
    if args.cmd == "run" and args.record and not (
            args.repo and args.fingerprint and args.run_id and args.db
            and args.verifier):
        print(json.dumps({"error": "--record needs --repo, --fingerprint, "
                                   "--run-id, --db and --verifier"}))
        return 2
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
