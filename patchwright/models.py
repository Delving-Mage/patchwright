"""Canonical data model. Every scanner is normalized into these types so the
rest of the pipeline never has to care which tool produced a finding."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> "Severity":
        return {
            "info": cls.INFO, "informational": cls.INFO, "note": cls.INFO,
            "low": cls.LOW, "warning": cls.LOW,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM,
            "high": cls.HIGH, "error": cls.HIGH,
            "critical": cls.CRITICAL,
        }.get((raw or "").strip().lower(), cls.MEDIUM)


class FindingKind(IntEnum):
    DEPENDENCY = 0   # SCA: vulnerable package
    CODE = 1         # SAST: vulnerable source pattern
    SECRET = 2       # leaked credential
    IAC = 3          # misconfiguration


@dataclass
class Finding:
    kind: FindingKind
    rule_id: str                    # CVE / Semgrep rule / secret type
    title: str
    severity: Severity
    file_path: str
    start_line: int
    end_line: int
    scanner: str                    # which tool reported it
    message: str = ""
    cve: Optional[str] = None
    cvss: Optional[float] = None
    package: Optional[str] = None
    installed_version: Optional[str] = None
    fixed_version: Optional[str] = None
    code_snippet: str = ""
    # populated later in the pipeline
    risk_score: float = 0.0
    reachable: Optional[bool] = None
    confirmed_by: list[str] = field(default_factory=list)  # scanners that agree
    # AI-discovery support: a finding surfaced by the LLM reasoning engine carries
    # an optional proof-of-concept test that FAILS on the vulnerable code. If that
    # PoC reproduces the bug, the finding is "confirmed" (executable evidence, not
    # the model's opinion); otherwise it stays "AI-suspected, unproven".
    poc_test: str = ""          # source of a test that demonstrates the vuln
    poc_test_rel: str = ""      # path the PoC should be written to in the repo
    confirmed: bool = False     # PoC reproduced the vuln on current code
    discovery_note: str = ""    # the model's one-line reasoning, for the report
    # org-internal identifier resolved per finding INSTANCE from the farm
    # service (see farm.py). Opaque string; empty when the service is not
    # configured or can't resolve this finding.
    farm_id: str = ""
    farm_status: str = ""       # farm's current state: open / fixed / suppressed ...
    suppressed: bool = False    # farm marked it accepted-risk / wontfix / false-pos
    farm_meta: dict = field(default_factory=dict)  # any extra enrichment from farm

    def fingerprint(self) -> str:
        """Stable identity used to dedupe the same vuln reported by N scanners."""
        if self.kind == FindingKind.DEPENDENCY:
            key = f"dep:{self.package}:{self.installed_version}:{self.cve or self.rule_id}"
        elif self.kind == FindingKind.SECRET:
            key = f"secret:{self.file_path}:{self.start_line}:{self.rule_id}"
        else:
            # code/iac: same rule on overlapping lines of same file == same finding
            key = f"{self.kind.name}:{self.file_path}:{self.start_line}:{self.rule_id}"
        return hashlib.sha1(key.encode()).hexdigest()[:16]

    @property
    def auto_fixable(self) -> bool:
        if self.kind == FindingKind.DEPENDENCY:
            return bool(self.fixed_version)        # deterministic: bump version
        if self.kind in (FindingKind.CODE, FindingKind.IAC):
            return True                            # attempt an AI patch
        if self.kind == FindingKind.SECRET:
            return False                           # never auto-rewrite a secret; flag for rotation
        return False

    def to_dict(self) -> dict:
        d = asdict(self)
        d["kind"] = self.kind.name
        d["severity"] = self.severity.name
        return d


@dataclass
class Patch:
    finding_fp: str
    file_path: str
    original: str
    patched: str
    rationale: str
    attempts: int = 1
    validated: bool = False
    validation_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
