"""Gitleaks: deep secret detection including full git history (Trivy only sees
the working tree). Two scanners on secrets => cross-confirmation in dedup."""
from __future__ import annotations

import os
import tempfile

from .base import Scanner
from ..models import Finding, FindingKind, Severity


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"

    def scan(self, repo_path: str) -> list[Finding]:
        import json
        report = os.path.join(tempfile.gettempdir(), "gitleaks.json")
        self._run(
            [self.binary, "detect", "--no-banner", "--redact",
             "--report-format", "json", "--report-path", report, "-s", repo_path],
            cwd=repo_path,
        )
        if not os.path.exists(report):
            return []
        try:
            with open(report) as fh:
                rows = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []

        findings: list[Finding] = []
        for r in rows or []:
            findings.append(Finding(
                kind=FindingKind.SECRET,
                rule_id=r.get("RuleID", ""),
                title=f"secret: {r.get('Description', r.get('RuleID',''))}",
                severity=Severity.CRITICAL,
                file_path=r.get("File", ""),
                start_line=r.get("StartLine", 0) or 0,
                end_line=r.get("EndLine", 0) or 0,
                scanner=self.name,
                message=f"Commit {r.get('Commit','')[:10]} by {r.get('Author','')}",
            ))
        return findings
