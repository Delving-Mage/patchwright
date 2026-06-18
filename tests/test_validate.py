"""The closed loop, the whole pitch. A patch is accepted ONLY when the re-scan
shows the finding gone AND the tests pass. We stub the scanner (re-scan result)
and drive the real test runner with a shell command so the accept/reject logic
is exercised end to end without needing semgrep/trivy installed."""
from patchwright.models import Finding, FindingKind, Severity
from patchwright import validate


def _finding():
    return Finding(
        kind=FindingKind.CODE, rule_id="python.lang.security.audit.eval",
        title="eval", severity=Severity.HIGH,
        file_path="app.py", start_line=1, end_line=1, scanner="semgrep",
    )


def _make_repo(tmp_path):
    (tmp_path / "app.py").write_text("x = eval(input())\n")
    return str(tmp_path)


def test_good_fix_accepted(tmp_path, monkeypatch):
    # re-scan reports the finding is gone, tests pass -> ACCEPTED
    monkeypatch.setattr(validate, "_rescan_file", lambda repo, f: [])
    ok, evidence = validate.validate_patch(
        _make_repo(tmp_path), _finding(), "app.py",
        "import ast\nx = ast.literal_eval(input())\n", test_cmd="true")
    assert ok is True
    assert any("resolved" in e for e in evidence)
    assert any("passed" in e for e in evidence)


def test_fix_that_breaks_tests_rejected(tmp_path, monkeypatch):
    # finding gone BUT tests fail -> REJECTED (a scanner-only autofixer ships this)
    monkeypatch.setattr(validate, "_rescan_file", lambda repo, f: [])
    ok, evidence = validate.validate_patch(
        _make_repo(tmp_path), _finding(), "app.py",
        "x = None\n", test_cmd="false")
    assert ok is False
    assert any("FAILED" in e for e in evidence)


def test_fix_that_leaves_vuln_rejected(tmp_path, monkeypatch):
    # re-scan still finds the SAME fingerprint -> REJECTED before tests even run
    f = _finding()
    monkeypatch.setattr(validate, "_rescan_file", lambda repo, fnd: [f])
    ok, evidence = validate.validate_patch(
        _make_repo(tmp_path), f, "app.py", "x = eval(input())\n", test_cmd="true")
    assert ok is False
    assert any("still present" in e for e in evidence)


def test_absolute_path_cannot_escape_sandbox(tmp_path, monkeypatch):
    # defense-in-depth: an absolute file_rel must be normalized back into sandbox
    monkeypatch.setattr(validate, "_rescan_file", lambda repo, f: [])
    repo = _make_repo(tmp_path)
    sentinel = tmp_path / "app.py"
    abs_path = str(sentinel)  # absolute path into the real repo
    validate.validate_patch(repo, _finding(), abs_path, "SAFE\n", test_cmd="true")
    # the REAL repo file must be untouched (patch only hit the sandbox copy)
    assert sentinel.read_text() == "x = eval(input())\n"
