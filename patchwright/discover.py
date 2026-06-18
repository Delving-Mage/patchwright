"""AI-discovery engine -- the "Mythos-inspired" layer.

Pattern scanners (Semgrep, Bandit, Trivy) only find what a rule already
describes. This module hands source code to the model and asks it to *reason*
about vulnerabilities the rules miss: logic flaws, broken authz, unsafe
deserialization, SSRF, injection through non-obvious data paths, TOCTOU, etc.

It is strictly DEFENSIVE. The model is asked to (a) locate a flaw and (b) write
a security TEST that demonstrates it so it can be fixed and proven fixed. It is
never asked to produce a working exploit, payload, or weaponized PoC.

Two modes (PW_AI_DISCOVERY / --discover):
  * augment (default): only re-examine files the OSS scanners already flagged,
    looking for related/adjacent flaws. Cheap, low false-positive.
  * deep: sweep every source file (capped). Widest net, more tokens.

Two credibility tiers:
  * CONFIRMED  -> the model produced a PoC test that FAILS on the current code,
    reproduced in a sandbox. Executable evidence; eligible for auto-fix + PR.
  * SUSPECTED  -> no reproducing PoC. Surfaced for human review, never auto-merged.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from . import context, llm
from .models import Finding, FindingKind, Severity

CODE_EXTS = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go",
             ".rb", ".php", ".cs", ".scala", ".c", ".cc", ".cpp", ".h")
_SKIP_DIRS = (".git", "node_modules", "venv", ".venv", "dist", "build",
              "target", ".gradle", "__pycache__", "vendor", "test", "tests")

MAX_FILES = int(os.environ.get("PW_DISCOVER_MAX_FILES", "40"))
MAX_BYTES = int(os.environ.get("PW_DISCOVER_MAX_BYTES", "20000"))


def _candidate_files(repo_path: str, existing: list[Finding], mode: str) -> list[str]:
    if mode == "augment":
        rels = {f.file_path for f in existing
                if f.kind in (FindingKind.CODE, FindingKind.IAC) and f.file_path}
        return [r for r in rels if r.lower().endswith(CODE_EXTS)][:MAX_FILES]
    # deep: walk the tree
    out: list[str] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if fn.lower().endswith(CODE_EXTS):
                rel = os.path.relpath(os.path.join(root, fn), repo_path)
                out.append(rel)
                if len(out) >= MAX_FILES:
                    return out
    return out


_DISCOVERY_PROMPT = """You are a defensive application-security auditor reviewing a single
source file for vulnerabilities that pattern-based scanners typically MISS:
broken authentication/authorization, insecure deserialization, SSRF, path
traversal, injection via non-obvious data flow, race conditions/TOCTOU, unsafe
crypto usage, and logic flaws.

Report only concrete, defensible issues in THIS file. Do not invent issues to
fill a quota. For each issue give the line, a short vuln class, a one-sentence
explanation of why it is exploitable, and a confidence 0-1.

File: {path}
```
{code}
```

Respond ONLY with a JSON array (no markdown), possibly empty:
[{{"line": <int>, "end_line": <int>, "vuln_class": "<slug eg insecure-deserialization>",
  "title": "<short>", "severity": "<low|medium|high|critical>",
  "explanation": "<one sentence>", "confidence": <0..1>}}]"""

_XFILE_PROMPT = """You are a defensive application-security auditor performing TAINT analysis
ACROSS multiple files. Untrusted input often enters in one file (a controller /
request handler) and reaches a dangerous sink in another (a service or repository
that runs SQL, executes commands, deserializes, reads files, makes requests).

Trace whether untrusted data from a SOURCE reaches a SINK without adequate
validation/encoding, following the data through the related files provided.
Report only concrete, defensible issues. Anchor each issue to a line in the
TARGET file. Give a short vuln class, a one-sentence explanation naming the
source->sink path, and confidence 0-1.

{context}

Respond ONLY with a JSON array (no markdown), possibly empty:
[{{"line": <int>, "end_line": <int>, "vuln_class": "<slug>",
  "title": "<short>", "severity": "<low|medium|high|critical>",
  "explanation": "<one sentence naming the source->sink flow>", "confidence": <0..1>}}]"""


def _read(repo_path: str, rel: str) -> str | None:
    try:
        with open(os.path.join(repo_path, rel), errors="ignore") as fh:
            return fh.read(MAX_BYTES)
    except OSError:
        return None


def _analyze_file(repo_path: str, rel: str, min_conf: float,
                  cross_file: bool = False) -> list[Finding]:
    code = _read(repo_path, rel)
    if not code:
        return []
    if cross_file:
        ctx = context.build_file_context(repo_path, rel)
        if ctx is None:
            return []
        # only spend the bigger cross-file call when there's an actual taint
        # surface (a source AND a sink somewhere in the neighborhood)
        if ctx.sources and ctx.sinks:
            numbered_target = "\n".join(
                f"{i+1:>5}  {ln}" for i, ln in enumerate(ctx.code.splitlines()))
            rendered = ctx.render(max_neighbor_bytes=3000).replace(
                ctx.code, numbered_target, 1)
            parsed = llm.complete_json(
                _XFILE_PROMPT.format(context=rendered), max_tokens=2500)
        else:
            numbered = "\n".join(
                f"{i+1:>5}  {ln}" for i, ln in enumerate(code.splitlines()))
            parsed = llm.complete_json(
                _DISCOVERY_PROMPT.format(path=rel, code=numbered), max_tokens=2000)
    else:
        numbered = "\n".join(f"{i+1:>5}  {ln}" for i, ln in enumerate(code.splitlines()))
        parsed = llm.complete_json(
            _DISCOVERY_PROMPT.format(path=rel, code=numbered), max_tokens=2000)
    if not isinstance(parsed, list):
        return []
    findings: list[Finding] = []
    for item in parsed:
        if not isinstance(item, dict):
            continue
        try:
            conf = float(item.get("confidence", 0.5))
        except (TypeError, ValueError):
            conf = 0.5
        if conf < min_conf:
            continue
        line = int(item.get("line", 0) or 0)
        vuln_class = str(item.get("vuln_class", "issue")).strip() or "issue"
        findings.append(Finding(
            kind=FindingKind.CODE,
            rule_id=f"ai.{vuln_class}",
            title=str(item.get("title", vuln_class))[:120],
            severity=Severity.parse(str(item.get("severity", "medium"))),
            file_path=rel,
            start_line=line,
            end_line=int(item.get("end_line", line) or line),
            scanner="ai-discovery",
            message=str(item.get("explanation", ""))[:500],
            discovery_note=str(item.get("explanation", ""))[:200],
        ))
    return findings


def _dedupe_against(ai: list[Finding], existing: list[Finding]) -> list[Finding]:
    """Drop AI findings that land on a line a scanner already flagged (the OSS
    tool owns it). Keeps the AI layer purely additive."""
    taken = {(f.file_path, f.start_line) for f in existing
             if f.kind == FindingKind.CODE}
    return [f for f in ai if (f.file_path, f.start_line) not in taken]


# --------------------------------------------------------------------------- #
# PoC confirmation: prove the vuln is real before it counts as "confirmed".    #
# --------------------------------------------------------------------------- #

_POC_PROMPT = """You are writing a DEFENSIVE security regression test (NOT an exploit).
Write a single self-contained pytest test that asserts the SECURE behavior for the
vulnerability below. On the CURRENT (vulnerable) code the test must FAIL; once the
code is fixed it must PASS. Do not write destructive code, network calls, or a
weaponized payload -- assert behavior with a benign, controlled input.

Vulnerability: {rule_id} -- {title}
File: {path} (around line {line})
Why: {explanation}

Relevant source:
```
{code}
```

Respond ONLY with JSON (no markdown):
{{"test_filename": "test_pw_poc_<short>.py", "test_code": "<complete pytest file>"}}"""


def _run_poc(sandbox: str, poc_rel: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["python", "-m", "pytest", poc_rel, "-q", "--no-header"],
            cwd=sandbox, capture_output=True, text=True, timeout=300)
        return proc.returncode, (proc.stdout + proc.stderr)[-600:]
    except Exception as e:  # noqa: BLE001
        return -1, f"poc run error: {e}"


def confirm_with_poc(repo_path: str, finding: Finding) -> Finding:
    """Ask the model for a PoC test; if it FAILS on current code (i.e. reproduces
    the vuln), mark the finding confirmed and attach the PoC so the validator can
    later require it to PASS after the fix. Python-only (pytest); other languages
    stay 'suspected'. Mutates and returns the finding."""
    code = _read(repo_path, finding.file_path)
    if not code or not finding.file_path.endswith(".py"):
        return finding
    parsed = llm.complete_json(_POC_PROMPT.format(
        rule_id=finding.rule_id, title=finding.title, path=finding.file_path,
        line=finding.start_line, explanation=finding.message, code=code),
        max_tokens=2000)
    if not isinstance(parsed, dict):
        return finding
    test_code = parsed.get("test_code")
    test_name = parsed.get("test_filename") or "test_pw_poc.py"
    if not test_code:
        return finding

    sandbox = tempfile.mkdtemp(prefix="pw_poc_")
    try:
        shutil.copytree(repo_path, sandbox, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns(".git", "node_modules",
                                                      "venv", "dist", "build"))
        poc_rel = os.path.basename(test_name)
        with open(os.path.join(sandbox, poc_rel), "w") as fh:
            fh.write(test_code)
        rc, _out = _run_poc(sandbox, poc_rel)
        # FAIL (rc==1) on vulnerable code == the test reproduces the vuln.
        if rc == 1:
            finding.confirmed = True
            finding.poc_test = test_code
            finding.poc_test_rel = poc_rel
            if "ai-poc" not in finding.confirmed_by:
                finding.confirmed_by.append("ai-poc")
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    return finding


def discover(repo_path: str, existing: list[Finding], mode: str = "augment",
             min_conf: float = 0.5, confirm: bool = True,
             cross_file: bool | None = None) -> list[Finding]:
    """Run AI discovery. Returns NEW findings (deduped against `existing`).

    cross_file enables taint-aware multi-file analysis (default: on for 'deep',
    off for 'augment' to save tokens). Override with PW_DISCOVER_XFILE=0/1."""
    if mode == "off" or not llm.available():
        return []
    if cross_file is None:
        env = os.environ.get("PW_DISCOVER_XFILE")
        cross_file = (env == "1") if env in ("0", "1") else (mode == "deep")
    files = _candidate_files(repo_path, existing, mode)
    found: list[Finding] = []
    for rel in files:
        found.extend(_analyze_file(repo_path, rel, min_conf, cross_file=cross_file))
    found = _dedupe_against(found, existing)
    if confirm:
        for f in found:
            confirm_with_poc(repo_path, f)
    return found
