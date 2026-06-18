"""Dedup + cross-confirmation: the same dependency CVE reported by two scanners
must collapse to ONE finding that records both scanners (and keeps the richest
data)."""
from patchwright.models import Finding, FindingKind, Severity
from patchwright import normalize


def _dep(scanner, severity=Severity.HIGH, fixed=None, cvss=None):
    return Finding(
        kind=FindingKind.DEPENDENCY,
        rule_id="CVE-2024-9999",
        cve="CVE-2024-9999",
        title="x", severity=severity,
        file_path="pom.xml", start_line=0, end_line=0,
        scanner=scanner,
        package="org.example:foo", installed_version="1.0.0",
        fixed_version=fixed, cvss=cvss,
    )


def test_same_cve_from_two_scanners_merges_and_cross_confirms():
    merged = normalize.merge([
        _dep("trivy", severity=Severity.MEDIUM),
        _dep("osv-scanner", severity=Severity.HIGH, fixed="1.0.1", cvss=7.5),
    ])
    assert len(merged) == 1
    f = merged[0]
    assert set(f.confirmed_by) == {"trivy", "osv-scanner"}
    # keeps the richer record: higher severity, the fix, the cvss
    assert f.severity == Severity.HIGH
    assert f.fixed_version == "1.0.1"
    assert f.cvss == 7.5


def test_distinct_cves_do_not_merge():
    a = _dep("trivy")
    b = _dep("trivy")
    b.cve = b.rule_id = "CVE-2024-0001"
    merged = normalize.merge([a, b])
    assert len(merged) == 2
