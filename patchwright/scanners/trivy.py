"""Trivy: dependencies, IaC misconfig, secrets. We use its JSON output."""
from __future__ import annotations

from .base import Scanner
from ..models import Finding, FindingKind, Severity


class TrivyScanner(Scanner):
    name = "trivy"
    binary = "trivy"

    def scan(self, repo_path: str) -> list[Finding]:
        import json
        out = self._run(
            [self.binary, "fs", "--quiet", "--format", "json",
             "--scanners", "vuln,misconfig,secret", repo_path],
            cwd=repo_path,
        )
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for result in data.get("Results", []):
            target = result.get("Target", "")
            for v in result.get("Vulnerabilities", []) or []:
                cvss = None
                for src in (v.get("CVSS") or {}).values():
                    cvss = src.get("V3Score") or cvss
                findings.append(Finding(
                    kind=FindingKind.DEPENDENCY,
                    rule_id=v.get("VulnerabilityID", ""),
                    cve=v.get("VulnerabilityID"),
                    title=v.get("Title") or v.get("VulnerabilityID", ""),
                    severity=Severity.parse(v.get("Severity", "")),
                    file_path=target,
                    start_line=0, end_line=0,
                    scanner=self.name,
                    message=v.get("Description", "")[:500],
                    cvss=cvss,
                    package=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                ))
            for m in result.get("Misconfigurations", []) or []:
                cm = m.get("CauseMetadata", {}) or {}
                findings.append(Finding(
                    kind=FindingKind.IAC,
                    rule_id=m.get("ID", ""),
                    title=m.get("Title", ""),
                    severity=Severity.parse(m.get("Severity", "")),
                    file_path=target,
                    start_line=cm.get("StartLine", 0) or 0,
                    end_line=cm.get("EndLine", 0) or 0,
                    scanner=self.name,
                    message=m.get("Resolution", ""),
                ))
            for s in result.get("Secrets", []) or []:
                findings.append(Finding(
                    kind=FindingKind.SECRET,
                    rule_id=s.get("RuleID", ""),
                    title=s.get("Title", "leaked secret"),
                    severity=Severity.parse(s.get("Severity", "CRITICAL")),
                    file_path=target,
                    start_line=s.get("StartLine", 0) or 0,
                    end_line=s.get("EndLine", 0) or 0,
                    scanner=self.name,
                    message="Potential secret detected",
                ))
        return findings
