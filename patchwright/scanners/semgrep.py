"""Semgrep: source-code SAST. We read its SARIF so the line ranges are exact,
which the remediation engine needs to build a tight context window."""
from __future__ import annotations

from .base import Scanner
from ..models import Finding, FindingKind, Severity


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary = "semgrep"

    def scan(self, repo_path: str) -> list[Finding]:
        import json
        import os
        # PW_SEMGREP_CONFIG lets you point at a local rules file/dir or a registry
        # ruleset (e.g. "p/python"); defaults to Semgrep's curated auto config.
        config = os.environ.get("PW_SEMGREP_CONFIG", "auto")
        out = self._run(
            [self.binary, "scan", "--config", config, "--sarif", "--quiet", repo_path],
            cwd=repo_path,
        )
        try:
            sarif = json.loads(out or "{}")
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for run in sarif.get("runs", []):
            # rule_id -> severity lookup from the driver metadata
            rule_sev = {}
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                lvl = (rule.get("defaultConfiguration", {}) or {}).get("level", "warning")
                rule_sev[rule.get("id")] = lvl
            for res in run.get("results", []):
                rid = res.get("ruleId", "")
                loc = (res.get("locations") or [{}])[0]
                phys = loc.get("physicalLocation", {})
                region = phys.get("region", {})
                path = phys.get("artifactLocation", {}).get("uri", "")
                findings.append(Finding(
                    kind=FindingKind.CODE,
                    rule_id=rid,
                    title=rid.split(".")[-1].replace("-", " "),
                    severity=Severity.parse(
                        res.get("level") or rule_sev.get(rid, "warning")),
                    file_path=path,
                    start_line=region.get("startLine", 0) or 0,
                    end_line=region.get("endLine", region.get("startLine", 0)) or 0,
                    scanner=self.name,
                    message=(res.get("message", {}) or {}).get("text", ""),
                ))
        return findings
