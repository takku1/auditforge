import hashlib
from dataclasses import dataclass, field
from typing import List, Any

@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    controls: tuple
    patterns: tuple
    remediation: str
    extensions: frozenset = frozenset()  # empty = all files
    value_group: int = 0  # capture group holding the secret value, if any
    # Exact basenames to match in addition to `extensions`, for extension-less
    # files like `Dockerfile`/`Dockerfile.dev` — scanners.py matches on
    # extension OR basename when both are set.
    filenames: frozenset = frozenset()
    # If True, a match containing an RFC 2606/6761 reserved-purpose or
    # non-routable pseudo-host suffix (.test/.example/.localhost/.invalid/
    # .local/.ipc/.internal) is skipped rather than reported — see
    # rules.RESERVED_SUFFIX_RE and docs/field-test-roninai-2026-08-25.md §G5/G7.
    check_reserved_suffix: bool = False


@dataclass
class Finding:
    rule: Rule
    severity: str          # effective severity (may be downgraded)
    file: str              # path relative to scan root
    line: int
    snippet: str
    in_test_context: bool
    # None = git awareness unavailable (not a repo, or git not on PATH);
    # True/False = whether `file` is currently tracked by git. See
    # docs/field-test-roninai-2026-08-25.md §G2 — remediation text for a
    # secret differs meaningfully (rotate now vs. was never committed).
    git_tracked: Any = None
    # True when this finding came from --history (git log -p --all), not a
    # scan of the working tree — see R-013. `file`/`line` still point at the
    # path/position within the commit's diff, not necessarily anything that
    # exists in the working tree today.
    historical: bool = False
    # For a historical finding: the short commit hash it was found in.
    commit: Any = None

    @property
    def fingerprint(self) -> str:
        h = hashlib.sha1(  # soc2-ignore: non-cryptographic dedup fingerprint
            f"{self.rule.id}|{self.file}|{self.snippet}".encode("utf-8", "replace")
        )
        return h.hexdigest()

    @property
    def effective_remediation(self) -> str:
        if self.historical:
            return (f"{self.rule.remediation} Found in git HISTORY"
                     f"{f' (commit {self.commit})' if self.commit else ''}, not "
                     "necessarily the working tree — if this is a real secret, "
                     "rotate it AND purge it from history (it's reachable via "
                     "`git log -p --all` regardless of the file's current content).")
        if self.git_tracked is True:
            return (f"{self.rule.remediation} This file is tracked by git — if this "
                     "value is a real secret, treat it as compromised: rotate it and "
                     "purge it from history, not just the working tree.")
        if self.git_tracked is False:
            return (f"{self.rule.remediation} This file is NOT tracked by git (local-only "
                     "or newly created) — if it's a real secret, moving/deleting it locally "
                     "is enough; no rotation is needed unless it was already pushed elsewhere.")
        return self.rule.remediation

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "category": self.rule.name,
            "severity": self.severity,
            "soc2_controls": list(self.rule.controls),
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "in_test_context": self.in_test_context,
            "git_tracked": self.git_tracked,
            "historical": self.historical,
            "commit": self.commit,
            "remediation": self.effective_remediation,
            "fingerprint": self.fingerprint,
        }


@dataclass
class UnifiedFinding:
    tool: str
    rule_id: str
    name: str
    severity: str
    file: str
    line: int
    snippet: str
    frameworks: List[str] = field(default_factory=list)
    remediation: str = ""
