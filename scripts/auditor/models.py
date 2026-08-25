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


@dataclass
class Finding:
    rule: Rule
    severity: str          # effective severity (may be downgraded)
    file: str              # path relative to scan root
    line: int
    snippet: str
    in_test_context: bool

    @property
    def fingerprint(self) -> str:
        h = hashlib.sha1(  # soc2-ignore: non-cryptographic dedup fingerprint
            f"{self.rule.id}|{self.file}|{self.snippet}".encode("utf-8", "replace")
        )
        return h.hexdigest()

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
            "remediation": self.rule.remediation,
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
