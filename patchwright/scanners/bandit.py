"""Bandit: Python-specific SAST. Semgrep covers many languages broadly; Bandit
adds Python-tuned checks (pickle, subprocess, weak crypto, yaml.load, ...).

Bandit broadens Python coverage beyond Semgrep's ruleset. Findings map to
FindingKind.CODE; each is validated by re-running the scanner that found it
(see validate._scanner_for_finding), so a Bandit fix is re-checked by Bandit."""
from __future__ import annotations

import json

from .base import Scanner
from ..models import Finding, FindingKind, Severity

_SEV = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}


class BanditScanner(Scanner):
    name = "bandit"
    binary = "bandit"

    def scan(self, repo_path: str) -> list[Finding]:
        out = self._run(
            [self.binary, "-r", repo_path, "-f", "json", "-q"],
            cwd=repo_path,
        )
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for r in data.get("results", []) or []:
            sev = _SEV.get((r.get("issue_severity") or "").upper(), Severity.MEDIUM)
            line = r.get("line_number", 0) or 0
            line_range = r.get("line_range") or [line]
            findings.append(Finding(
                kind=FindingKind.CODE,
                rule_id=r.get("test_id", ""),
                title=r.get("test_name", "") or r.get("test_id", ""),
                severity=sev,
                file_path=r.get("filename", ""),
                start_line=line,
                end_line=max(line_range) if line_range else line,
                scanner=self.name,
                message=(r.get("issue_text", "") or "")[:500],
            ))
        return findings
