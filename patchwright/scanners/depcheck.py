"""OWASP Dependency-Check: a third independent SCA engine (alongside Trivy + OSV).

Why a third one: recall on dependency CVEs is a union problem -- each engine's
advisory sources and version-range logic differ, so a third opinion strictly
widens coverage, and overlap with Trivy/OSV on the same CVE becomes cross-
confirmation. Especially strong on the Java/Maven/Gradle ecosystem.

Dependency-Check writes a JSON report (it doesn't stream to stdout), so we point
it at a temp report file and parse that."""
from __future__ import annotations

import json
import os
import tempfile

from .base import Scanner
from ..models import Finding, FindingKind, Severity


class DependencyCheckScanner(Scanner):
    name = "dependency-check"
    binary = "dependency-check"

    def scan(self, repo_path: str) -> list[Finding]:
        report = os.path.join(tempfile.gettempdir(), "pw_depcheck.json")
        self._run(
            [self.binary, "--scan", repo_path, "--format", "JSON",
             "--out", report, "--prettyPrint", "false"],
            cwd=repo_path,
        )
        # the binary may write to a dir; normalize to the file
        if os.path.isdir(report):
            report = os.path.join(report, "dependency-check-report.json")
        if not os.path.exists(report):
            return []
        try:
            with open(report) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return []

        findings: list[Finding] = []
        for dep in data.get("dependencies", []) or []:
            file_path = dep.get("filePath") or dep.get("fileName", "")
            # best-effort package + version from the first identifier
            pkg = ver = None
            for ident in dep.get("packages", []) or dep.get("identifiers", []) or []:
                pid = ident.get("id", "")
                if "@" in pid:
                    pkg, _, ver = pid.rpartition("@")
                    pkg = pkg.split("/")[-1]
                break
            for v in (dep.get("vulnerabilities") or []):
                cvss = None
                cs = v.get("cvssv3") or {}
                if isinstance(cs, dict):
                    cvss = cs.get("baseScore")
                findings.append(Finding(
                    kind=FindingKind.DEPENDENCY,
                    rule_id=v.get("name", ""),
                    cve=v.get("name") if str(v.get("name", "")).startswith("CVE-") else None,
                    title=v.get("name", ""),
                    severity=Severity.parse(v.get("severity", "")),
                    file_path=file_path,
                    start_line=0, end_line=0,
                    scanner=self.name,
                    message=(v.get("description", "") or "")[:500],
                    cvss=cvss,
                    package=pkg,
                    installed_version=ver,
                ))
        return findings
