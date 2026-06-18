"""Fan-in: merge findings from every scanner into one deduplicated list.

Differentiator vs single-scanner tools: when two independent scanners report the
same vuln we don't show it twice -- we MERGE them and record cross-confirmation,
which later boosts the risk score and the fix confidence (agreement => signal)."""
from __future__ import annotations

from .models import Finding


def merge(findings: list[Finding]) -> list[Finding]:
    by_fp: dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint()
        if fp not in by_fp:
            f.confirmed_by = [f.scanner]
            by_fp[fp] = f
            continue
        existing = by_fp[fp]
        if f.scanner not in existing.confirmed_by:
            existing.confirmed_by.append(f.scanner)
        # keep the richest record: prefer one that carries a fix + higher severity
        if (f.fixed_version and not existing.fixed_version):
            existing.fixed_version = f.fixed_version
        if f.severity > existing.severity:
            existing.severity = f.severity
        if f.cvss and not existing.cvss:
            existing.cvss = f.cvss
    return list(by_fp.values())


def cross_confirm_by_location(findings: list[Finding], window: int = 3) -> list[Finding]:
    """Code/IaC findings from DIFFERENT engines that land on the same file within
    `window` lines almost certainly describe the same defect -- but their rule_ids
    differ, so fingerprint dedup keeps them separate. We don't merge them (that
    would cost recall); instead we record the cross-engine agreement in each
    finding's `confirmed_by`, which boosts the risk score and fix confidence.

    This is the trust signal a single-engine tool (e.g. Snyk) structurally cannot
    produce: independent corroboration."""
    from .models import FindingKind
    code_like = [f for f in findings
                 if f.kind in (FindingKind.CODE, FindingKind.IAC) and f.start_line]
    for i, a in enumerate(code_like):
        for b in code_like[i + 1:]:
            if a.scanner == b.scanner:
                continue
            if a.file_path != b.file_path:
                continue
            if abs(a.start_line - b.start_line) > window:
                continue
            if b.scanner not in a.confirmed_by:
                a.confirmed_by.append(b.scanner)
            if a.scanner not in b.confirmed_by:
                b.confirmed_by.append(a.scanner)
    return findings
