"""Orchestrator: scan -> merge -> prioritize -> remediate -> report."""
from __future__ import annotations

import concurrent.futures
import os
from dataclasses import dataclass, field

from . import discover, normalize, prioritize
from .farm import FarmClient
from .models import Finding, Patch
from .remediate import remediate
from .scanners import ALL_SCANNERS


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    patches: list[Patch] = field(default_factory=list)
    scanners_used: list[str] = field(default_factory=list)
    pr_url: str = ""                       # set by the PR step; synced to farm
    farm_sync: dict = field(default_factory=dict)  # result of the farm sync

    @property
    def validated_fixes(self) -> list[Patch]:
        return [p for p in self.patches if p.validated]

    @property
    def ai_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.scanner == "ai-discovery"]

    @property
    def ai_confirmed(self) -> list[Finding]:
        return [f for f in self.ai_findings if f.confirmed]

    def summary(self) -> dict:
        ai = self.ai_findings
        return {
            "total_findings": len(self.findings),
            "auto_fixed_validated": len(self.validated_fixes),
            "needs_review": len(self.findings) - len(self.validated_fixes),
            "ai_discovered": len(ai),
            "ai_confirmed_by_poc": sum(1 for f in ai if f.confirmed),
            "farm_resolved": sum(1 for f in self.findings if f.farm_id),
            "farm_suppressed": sum(1 for f in self.findings if f.suppressed),
            "farm_sync": self.farm_sync,
            "by_severity": {
                s: sum(1 for f in self.findings if f.severity.name == s)
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
            "scanners": self.scanners_used,
        }


def _relativize(findings: list[Finding], repo_path: str) -> None:
    repo_abs = os.path.abspath(repo_path)
    for f in findings:
        if f.file_path and os.path.isabs(f.file_path):
            try:
                f.file_path = os.path.relpath(f.file_path, repo_abs)
            except ValueError:
                pass


def run(repo_path: str, test_cmd: str | None = None, fix: bool = True,
        max_findings_to_fix: int = 50, discover_mode: str = "augment",
        sync: bool = True) -> Report:
    report = Report()
    farm = FarmClient.from_env()

    # 1. scan with every available scanner, in parallel
    scanners = [cls() for cls in ALL_SCANNERS]
    active = [s for s in scanners if s.available()]
    report.scanners_used = [s.name for s in active]

    raw: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(active) or 1) as ex:
        for result in ex.map(lambda s: s.scan(repo_path), active):
            raw.extend(result)

    # 2. dedup + cross-confirm
    # normalize paths to repo-relative: scanners emit absolute paths, and
    # os.path.join(sandbox, abs_path) silently escapes the sandbox.
    merged = normalize.merge(raw)
    _relativize(merged, repo_path)

    # 2b. AI discovery -- reason about vulns the rule engines miss, then prove
    # the real ones with a PoC test. Additive: deduped against scanner findings.
    if discover_mode and discover_mode != "off":
        ai = discover.discover(repo_path, merged, mode=discover_mode)
        report.scanners_used = report.scanners_used + (["ai-discovery"] if ai else [])
        merged = merged + ai

    # 2c. cross-engine consensus by location (boosts trust without losing recall)
    normalize.cross_confirm_by_location(merged)

    # 3. contextual prioritization
    report.findings = prioritize.score(merged, repo_path)

    # 3b. resolve + enrich from the Farm system-of-record (farm-id, status,
    # suppression). Runs for every command so findings carry their org identity.
    if farm and farm.enabled:
        farm.resolve(report.findings)

    # 4. remediate the highest-risk, auto-fixable findings first.
    # AI-discovery findings are only auto-fixed when PoC-CONFIRMED -- an
    # unproven AI hunch never gets silently patched; it's surfaced for review.
    # Farm-suppressed findings (accepted-risk / wontfix) are never re-fixed.
    if fix:
        def _fixable(f: Finding) -> bool:
            if not f.auto_fixable or f.suppressed:
                return False
            if f.scanner == "ai-discovery" and not f.confirmed:
                return False
            return True
        targets = [f for f in report.findings if _fixable(f)][:max_findings_to_fix]
        for f in targets:
            patch = remediate(repo_path, f, test_cmd)
            if patch:
                report.patches.append(patch)

    # 5. sync proven results back to Farm (idempotent, evidence-rich). Done after
    # fixing so FIXED_VALIDATED carries the re-scan/test/PoC proof.
    if farm and farm.enabled and sync and fix:
        report.farm_sync = farm.sync(report)

    return report
