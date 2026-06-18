"""Tests for the depth/trust/safety hardening pass: location consensus, the
confirm-factor fix, the syntax gate, the destructive-patch guard, and Youden."""
from patchwright import normalize, validate
from patchwright.models import Finding, FindingKind, Severity
from patchwright.remediate import _too_destructive
from patchwright.benchmark.score import GroundTruth, score


def _code(scanner, file="A.java", line=42, rule="r"):
    return Finding(kind=FindingKind.CODE, rule_id=rule, title="t",
                   severity=Severity.HIGH, file_path=file, start_line=line,
                   end_line=line, scanner=scanner)


def test_location_consensus_records_agreement_without_merging():
    a = _code("semgrep", line=42, rule="semgrep.sqli")
    b = _code("snyk-like", line=44, rule="other.sqli")   # different rule_id, +2 lines
    out = normalize.cross_confirm_by_location([a, b], window=3)
    assert len(out) == 2                                 # NOT merged -> recall kept
    assert "snyk-like" in a.confirmed_by
    assert "semgrep" in b.confirmed_by


def test_consensus_ignores_same_scanner_and_far_lines():
    a = _code("semgrep", line=10, rule="x")
    b = _code("semgrep", line=11, rule="y")              # same scanner -> no boost
    c = _code("bandit", line=80, rule="z")               # too far -> no boost
    normalize.cross_confirm_by_location([a, b, c], window=3)
    assert a.confirmed_by == [] and b.confirmed_by == []
    assert c.confirmed_by == []


def test_syntax_gate_rejects_broken_python():
    ok, msg = validate.syntax_ok("x.py", "def f(:\n  pass")
    assert ok is False and "parse error" in msg


def test_syntax_gate_accepts_valid_python_and_balanced_java():
    assert validate.syntax_ok("x.py", "def f():\n    return 1\n")[0] is True
    assert validate.syntax_ok("X.java", "class X { void m(){} }")[0] is True
    assert validate.syntax_ok("X.java", "class X { void m({}")[0] is False


def test_destructive_guard():
    original = "\n".join(f"line {i}" for i in range(60))
    assert _too_destructive(original, "x = 1\n") is True          # gutted
    assert _too_destructive(original, original + "\n# fix") is False  # minimal


def test_youden_score_location_mode():
    gt = GroundTruth(match="location", line_tolerance=1, items=[
        {"file": "a.py", "line": 10, "label": True},
        {"file": "b.py", "line": 20, "label": True},
        {"file": "s.py", "line": 5, "label": False},     # safe -> TN if not flagged
    ])
    findings = [{"file_path": "a.py", "start_line": 10, "rule_id": "x"}]  # 1 TP
    m = score("t", findings, gt)
    assert (m.tp, m.fn, m.fp, m.tn) == (1, 1, 0, 1)
    assert m.recall == 0.5 and m.fpr == 0.0
    assert m.youden == 0.5
