"""Contextual prioritization: an unreachable (un-imported) CVSS-10 dependency
must rank BELOW a reachable HIGH code finding. This is the noise-reduction that
separates Patchwright from "sort by raw CVSS" tools."""
from patchwright.models import Finding, FindingKind, Severity
from patchwright import prioritize


def _unused_critical_dep():
    return Finding(
        kind=FindingKind.DEPENDENCY, rule_id="CVE-2024-1111", cve="CVE-2024-1111",
        title="crit dep", severity=Severity.CRITICAL,
        file_path="pom.xml", start_line=0, end_line=0,
        scanner="trivy", package="com.vulnerable:vulnlib",
        installed_version="1.0.0", fixed_version="1.0.1", cvss=10.0,
    )


def _reachable_high_code():
    return Finding(
        kind=FindingKind.CODE, rule_id="java.lang.security.audit.rce",
        title="rce", severity=Severity.HIGH,
        file_path="src/App.java", start_line=10, end_line=10,
        scanner="semgrep",
    )


def test_unreachable_dep_ranks_below_reachable_code(tmp_path):
    # repo that never imports com.vulnerable.* -> dep is unreachable
    (tmp_path / "App.java").write_text("public class App { void m(){} }")
    ranked = prioritize.score(
        [_unused_critical_dep(), _reachable_high_code()], str(tmp_path))
    assert ranked[0].kind == FindingKind.CODE
    assert ranked[1].kind == FindingKind.DEPENDENCY
    assert ranked[1].reachable is False


def test_reachable_dep_keeps_full_weight(tmp_path):
    # now the dep IS imported -> reachable, should outrank the HIGH code finding
    (tmp_path / "App.java").write_text(
        "import com.vulnerable.vulnlib.Thing;\npublic class App {}")
    ranked = prioritize.score(
        [_unused_critical_dep(), _reachable_high_code()], str(tmp_path))
    assert ranked[0].kind == FindingKind.DEPENDENCY
    assert ranked[0].reachable is True
