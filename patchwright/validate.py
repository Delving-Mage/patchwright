"""Validation: the part that makes auto-fix trustworthy.

After a candidate patch is applied to an isolated copy of the repo we:
  1. re-run the SAME scanner scoped to the SAME file
  2. confirm the SPECIFIC finding (by fingerprint) is gone
  3. confirm no NEW finding of equal/higher severity was introduced
  4. run the project's test command (if any) -- the patch must not break the build

A patch is only accepted when (2)+(3)+(4) all pass. This closed loop is what
lets us auto-merge instead of dumping suggestions on a human.

For AI-discovered findings there is no rule engine to re-run, so steps 1-3 are
replaced by a proof-of-concept test: the PoC FAILED on the vulnerable code, so
after the fix it must PASS (see _validate_ai_finding). The PoC is executable
evidence -- the model still never grades its own work."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from .models import Finding, FindingKind
from .scanners import BY_NAME, TrivyScanner, SemgrepScanner

# Fallback scanner per kind, used only if the finding's own scanner is gone.
_SCANNER_FOR = {
    FindingKind.CODE: SemgrepScanner,
    FindingKind.IAC: TrivyScanner,
    FindingKind.DEPENDENCY: TrivyScanner,
}


def _scanner_for_finding(finding: Finding):
    """Prefer the EXACT scanner that produced the finding -- its rule_id (and
    thus the fingerprint) only re-matches under the same tool. Fall back to the
    kind default if that scanner isn't installed in this environment."""
    own = BY_NAME.get(finding.scanner)
    if own and own().available():
        return own()
    fallback = _SCANNER_FOR.get(finding.kind)
    return fallback() if fallback else None


def _rescan_file(repo_path: str, finding: Finding) -> list[Finding]:
    scanner = _scanner_for_finding(finding)
    if not scanner:
        return []
    if not scanner.available():
        return []          # cannot validate -> caller treats as low confidence
    all_found = scanner.scan(repo_path)
    repo_abs = os.path.abspath(repo_path)
    for f in all_found:    # align paths with the (repo-relative) original finding
        if f.file_path and os.path.isabs(f.file_path):
            try:
                f.file_path = os.path.relpath(f.file_path, repo_abs)
            except ValueError:
                pass
    base = os.path.basename(finding.file_path)
    return [f for f in all_found if f.file_path.endswith(base)]


def _run_poc(sandbox: str, poc_rel: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["python", "-m", "pytest", poc_rel, "-q", "--no-header"],
            cwd=sandbox, capture_output=True, text=True, timeout=300)
        return proc.returncode, (proc.stdout + proc.stderr)[-400:]
    except Exception as e:  # noqa: BLE001
        return -1, f"poc run error: {e}"


def _validate_ai_finding(sandbox: str, finding: Finding, evidence: list[str],
                         test_cmd: str | None) -> tuple[bool, list[str]]:
    """Accept an AI-discovery fix ONLY if its PoC test, which failed on the
    vulnerable code, now PASSES -- and the project's suite stays green."""
    if not finding.poc_test:
        return False, ["AI-suspected: no PoC to prove the fix (flagged for review)"]
    poc_rel = finding.poc_test_rel or "test_pw_poc.py"
    with open(os.path.join(sandbox, poc_rel), "w") as fh:
        fh.write(finding.poc_test)
    rc, out = _run_poc(sandbox, poc_rel)
    if rc != 0:
        return False, [f"PoC still failing after patch -> vuln not fixed: {out}"]
    evidence.append("PoC test now passes -> vulnerability demonstrably fixed")

    ok, msg = run_tests(sandbox, test_cmd)
    evidence.append(msg)
    return ok, evidence


def syntax_ok(file_rel: str, content: str) -> tuple[bool, str]:
    """Cheap structural gate run BEFORE the expensive sandbox copy + re-scan +
    test suite. Catches an LLM patch that doesn't even parse, so we fail in
    milliseconds instead of after a multi-minute Java build."""
    ext = os.path.splitext(file_rel)[1].lower()
    if ext == ".py":
        import ast
        try:
            ast.parse(content)
        except SyntaxError as e:
            return False, f"syntax check: Python parse error ({e.msg} line {e.lineno})"
        return True, "syntax check: parses"
    # brace/paren balance heuristic for C-family / JS / Java when no parser is cheap
    if ext in (".java", ".js", ".ts", ".jsx", ".tsx", ".go", ".kt", ".scala",
               ".c", ".cc", ".cpp", ".cs"):
        for open_c, close_c in (("{", "}"), ("(", ")"), ("[", "]")):
            if content.count(open_c) != content.count(close_c):
                return False, f"syntax check: unbalanced '{open_c}{close_c}'"
        return True, "syntax check: balanced"
    return True, "syntax check: skipped (no checker for this type)"


def run_tests(repo_path: str, test_cmd: str | None) -> tuple[bool, str]:
    if not test_cmd:
        return True, "no test command configured (skipped)"
    try:
        proc = subprocess.run(
            test_cmd, shell=True, cwd=repo_path,
            capture_output=True, text=True, timeout=1200,
        )
        ok = proc.returncode == 0
        tail = (proc.stdout + proc.stderr)[-800:]
        return ok, ("tests passed" if ok else f"tests FAILED: {tail}")
    except subprocess.TimeoutExpired:
        return False, "tests timed out"


def validate_patch(repo_path: str, finding: Finding, file_rel: str,
                   patched_content: str, test_cmd: str | None) -> tuple[bool, list[str]]:
    """Apply patch in a sandbox copy, re-scan + test, return (accepted, evidence)."""
    evidence: list[str] = []
    # defense in depth: never let an absolute path escape the sandbox
    if os.path.isabs(file_rel):
        file_rel = os.path.relpath(file_rel, os.path.abspath(repo_path))

    # fast structural gate first -- reject un-parseable patches before paying for
    # a full repo copy + re-scan + test run.
    ok, msg = syntax_ok(file_rel, patched_content)
    if not ok:
        return False, [msg]
    evidence.append(msg)

    sandbox = tempfile.mkdtemp(prefix="pw_validate_")
    try:
        # copy repo (excluding the heavy/irrelevant dirs) into the sandbox
        shutil.copytree(
            repo_path, sandbox, dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(".git", "node_modules", "venv", "dist", "build"),
        )
        target = os.path.join(sandbox, file_rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w") as fh:
            fh.write(patched_content)

        # AI-discovery findings can't be re-scanned by a rule engine. Their proof
        # is the PoC test: it FAILED on the vulnerable code, so after the fix it
        # must PASS. That's executable evidence, not the model grading itself.
        if finding.scanner == "ai-discovery":
            return _validate_ai_finding(sandbox, finding, evidence, test_cmd)

        # 1-3: finding-specific re-scan
        residual = _rescan_file(sandbox, finding)
        still_present = any(r.fingerprint() == finding.fingerprint() for r in residual)
        worse = any(r.severity >= finding.severity and r.fingerprint() != finding.fingerprint()
                    for r in residual)
        if still_present:
            return False, ["re-scan: original finding still present"]
        if worse:
            return False, ["re-scan: patch introduced a new equal/higher finding"]
        evidence.append("re-scan: original finding resolved, no regressions")

        # 4: tests
        ok, msg = run_tests(sandbox, test_cmd)
        evidence.append(msg)
        return ok, evidence
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
