"""Checkov: deep IaC / config misconfiguration scanner (Terraform, CloudFormation,
Kubernetes, Dockerfile, Helm, GitHub Actions, Bitbucket Pipelines, ...).

Trivy also does IaC, but Checkov carries a much larger policy set for cloud
posture. Running both => cross-confirmation on misconfigs and broader coverage.
Findings are mapped to FindingKind.IAC so the validator re-scans them with the
IaC scanner after a candidate patch, same as any other finding."""
from __future__ import annotations

import json
import os

from .base import Scanner
from ..models import Finding, FindingKind, Severity

# Checkov rarely sets a severity in CE output; infer from the check id family or
# default to MEDIUM. Secrets checks (CKV_SECRET_*) are treated as SECRET kind.
_GUESS_HIGH = ("ENCRYPT", "PUBLIC", "PUBLICLY", "0.0.0.0", "ADMIN", "ROOT", "PRIVILEGED")


class CheckovScanner(Scanner):
    name = "checkov"
    binary = "checkov"

    def scan(self, repo_path: str) -> list[Finding]:
        out = self._run(
            [self.binary, "-d", repo_path, "-o", "json", "--compact",
             "--quiet", "--soft-fail"],
            cwd=repo_path,
        )
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return []

        # checkov emits either a single object or a list (one per framework)
        blocks = data if isinstance(data, list) else [data]
        findings: list[Finding] = []
        for block in blocks:
            failed = (block.get("results", {}) or {}).get("failed_checks", []) or []
            for c in failed:
                check_id = c.get("check_id", "")
                check_name = c.get("check_name", "")
                path = c.get("file_path", "") or c.get("repo_file_path", "")
                path = path.lstrip("/")  # checkov prefixes a leading slash
                lines = c.get("file_line_range", [0, 0]) or [0, 0]
                sev = c.get("severity")  # only set with the platform/PRO key
                if sev:
                    severity = Severity.parse(sev)
                else:
                    upper = (check_id + " " + check_name).upper()
                    severity = (Severity.HIGH if any(k in upper for k in _GUESS_HIGH)
                                else Severity.MEDIUM)
                is_secret = check_id.startswith("CKV_SECRET")
                findings.append(Finding(
                    kind=FindingKind.SECRET if is_secret else FindingKind.IAC,
                    rule_id=check_id,
                    title=check_name or check_id,
                    severity=Severity.CRITICAL if is_secret else severity,
                    file_path=path,
                    start_line=lines[0] or 0,
                    end_line=lines[1] if len(lines) > 1 else (lines[0] or 0),
                    scanner=self.name,
                    message=(c.get("guideline") or check_name or "")[:500],
                ))
        return findings
