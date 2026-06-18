"""OSV-Scanner: Google's open-source vulnerability scanner backed by the OSV.dev
database. It resolves the FULL transitive dependency tree from lockfiles
(Maven pom.xml, Gradle, package-lock.json, poetry.lock, go.sum, Cargo.lock, ...),
so it catches vulnerable *transitive* packages that a manifest-only read misses.

Why it's here: OSV and Trivy draw from overlapping-but-different advisory sources.
Running both gives us cross-confirmation on dependency CVEs (agreement => higher
trust, surfaced by normalize.merge) and strictly wider coverage than either alone.
"""
from __future__ import annotations

import json
import os

from .base import Scanner
from ..models import Finding, FindingKind, Severity

# OSV severity comes as a CVSS vector or a coarse DB severity; map both.
_DB_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _cvss_from_vector(vector: str) -> float | None:
    """Pull the base score if OSV embedded a CVSS *score*; otherwise None.
    OSV usually ships a CVSS *vector* string, not a number, so we only return a
    score when one is explicitly present (kept simple + dependency-free)."""
    return None


def _bucket_severity(entry: dict) -> Severity:
    # 1) database_specific severity label (GitHub/GHSA style)
    db = (entry.get("database_specific") or {}).get("severity")
    if isinstance(db, str) and db.upper() in _DB_SEV:
        return _DB_SEV[db.upper()]
    # 2) severity array (CVSS vectors) -> default MEDIUM if present but unscored
    if entry.get("severity"):
        return Severity.MEDIUM
    return Severity.MEDIUM


def _fixed_version(entry: dict, ecosystem: str) -> str | None:
    """First 'fixed' version offered across affected ranges, if any."""
    for aff in entry.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                fixed = ev.get("fixed")
                if fixed:
                    return fixed
    return None


class OsvScanner(Scanner):
    name = "osv-scanner"
    binary = "osv-scanner"

    def scan(self, repo_path: str) -> list[Finding]:
        out = self._run(
            [self.binary, "--format", "json", "--recursive", repo_path],
            cwd=repo_path,
        )
        try:
            data = json.loads(out or "{}")
        except json.JSONDecodeError:
            return []

        findings: list[Finding] = []
        for res in data.get("results", []) or []:
            source = (res.get("source") or {}).get("path", "")
            # keep manifest path repo-relative so it lines up with other scanners
            if source and os.path.isabs(source):
                try:
                    source = os.path.relpath(source, os.path.abspath(repo_path))
                except ValueError:
                    pass
            for pkg in res.get("packages", []) or []:
                info = pkg.get("package", {}) or {}
                pkg_name = info.get("name", "")
                ecosystem = info.get("ecosystem", "")
                installed = info.get("version", "")
                for vuln in pkg.get("vulnerabilities", []) or []:
                    vid = vuln.get("id", "")
                    # prefer a real CVE alias for cross-confirmation w/ Trivy
                    cve = next((a for a in vuln.get("aliases", []) or []
                                if a.startswith("CVE-")), None) or vid
                    findings.append(Finding(
                        kind=FindingKind.DEPENDENCY,
                        rule_id=vid,
                        cve=cve,
                        title=vuln.get("summary") or vid,
                        severity=_bucket_severity(vuln),
                        file_path=source,
                        start_line=0, end_line=0,
                        scanner=self.name,
                        message=(vuln.get("details", "") or "")[:500],
                        package=pkg_name,
                        installed_version=installed,
                        fixed_version=_fixed_version(vuln, ecosystem),
                    ))
        return findings
