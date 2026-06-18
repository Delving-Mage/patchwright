"""Remediation engine.

For dependency vulns the fix is deterministic (pin the fixed version).
For code/IaC findings we ask an LLM for a MINIMAL-diff patch, then hand it to the
validator. If validation fails we feed the failure reason back to the model and
retry (up to max_attempts). The model never gets to "approve" its own work -- the
scanner + test suite are the judge."""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .models import Finding, FindingKind, Patch
from .validate import validate_patch

ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-opus-4-8"


def _too_destructive(original: str, patched: str) -> bool:
    """A security fix should be a tight change, not a rewrite. If the candidate
    drops most of the file (truncated output, gutted logic) we reject it -- that's
    how scanner-only autofixers ship 'the vuln is gone because the code is gone'.
    The validator's test suite is the backstop, but catching it here saves a
    full validation cycle and avoids accidental data loss."""
    o_lines, p_lines = original.splitlines(), patched.splitlines()
    if len(original) > 200 and len(patched) < 0.3 * len(original):
        return True
    if len(o_lines) > 20 and len(p_lines) < 0.5 * len(o_lines):
        return True
    return False


def _read(repo_path: str, rel: str) -> str | None:
    p = os.path.join(repo_path, rel)
    try:
        with open(p, errors="ignore") as fh:
            return fh.read()
    except OSError:
        return None


def _llm_patch(file_content: str, finding: Finding, feedback: str | None) -> tuple[str, str] | None:
    """Return (patched_file_content, rationale) or None. Requires ANTHROPIC_API_KEY."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None

    window = "\n".join(
        f"{i+1:>5}  {ln}" for i, ln in enumerate(file_content.splitlines())
    )
    retry = f"\nA previous attempt was REJECTED by validation: {feedback}\nFix that and try again." if feedback else ""
    prompt = f"""You are a security remediation engine. Produce the MINIMAL change that
fixes the vulnerability below without altering unrelated behavior.

Vulnerability: {finding.rule_id} ({finding.severity.name})
Location: {finding.file_path} lines {finding.start_line}-{finding.end_line}
Detail: {finding.message}{retry}

Full file (line-numbered):
{window}

Respond ONLY with JSON, no markdown:
{{"patched_file": "<the COMPLETE file with the fix applied>",
  "rationale": "<one sentence: what you changed and why it closes the vuln>"}}"""

    body = json.dumps({
        "model": MODEL,
        "max_tokens": 8000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        ANTHROPIC_URL, data=body,
        headers={"content-type": "application/json",
                 "x-api-key": key,
                 "anthropic-version": "2023-06-01"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    text = re.sub(r"^```(?:json)?|```$", "", text.strip()).strip()
    try:
        parsed = json.loads(text)
        return parsed["patched_file"], parsed.get("rationale", "")
    except (json.JSONDecodeError, KeyError):
        return None


def _maven_patch(content: str, package: str, fixed_version: str) -> str | None:
    """Pin a fixed version in a Maven pom.xml.

    Maven coordinates arrive as 'groupId:artifactId'. The <version> sits in a
    sibling element inside the <dependency> block and may be:
      (a) a literal:        <version>1.2.3</version>
      (b) a property ref:   <version>${foo.version}</version>  (defined in
          <properties>); in that case we bump the property, which is the correct
          single-source-of-truth fix Maven projects expect.
    """
    if ":" not in package:
        return None
    group_id, _, artifact_id = package.partition(":")
    # locate the SINGLE <dependency> block that declares this artifactId.
    # the tempered token (?:(?!</dependency>).)*? stops the match from spilling
    # across neighbouring dependency blocks, so we bump the right version even
    # when the target isn't the first dependency in the file.
    inner = r"(?:(?!</?dependency>).)*?"
    dep_re = re.compile(
        r"(<dependency>" + inner + r"<artifactId>\s*" + re.escape(artifact_id) +
        r"\s*</artifactId>" + inner + r"</dependency>)",
        re.DOTALL,
    )
    m = dep_re.search(content)
    if not m:
        return None
    block = m.group(1)
    ver_re = re.compile(r"(<version>\s*)([^<]*?)(\s*</version>)", re.DOTALL)
    vm = ver_re.search(block)
    if not vm:
        return None
    current = vm.group(2).strip()

    # (b) property reference -> bump the property definition instead
    prop = re.fullmatch(r"\$\{([^}]+)\}", current)
    if prop:
        prop_name = prop.group(1)
        prop_re = re.compile(
            r"(<" + re.escape(prop_name) + r">\s*)([^<]*?)(\s*</" +
            re.escape(prop_name) + r">)")
        patched, n = prop_re.subn(rf"\g<1>{fixed_version}\g<3>", content, count=1)
        return patched if n else None

    # (a) literal version inside the matched dependency block
    new_block = block[:vm.start()] + vm.group(1) + fixed_version + vm.group(3) + block[vm.end():]
    return content[:m.start(1)] + new_block + content[m.end(1):]


def _dependency_patch(repo_path: str, finding: Finding) -> Patch | None:
    """Deterministic: pin the fixed version in the manifest. No LLM needed.

    Maven pom.xml gets dedicated XML-aware handling; requirements.txt /
    package.json / build.gradle / Cargo.toml etc. use the loose pin regex."""
    rel = finding.file_path
    content = _read(repo_path, rel)
    if content is None or not finding.fixed_version or not finding.package:
        return None

    patched = None
    if os.path.basename(rel).lower() == "pom.xml":
        patched = _maven_patch(content, finding.package, finding.fixed_version)

    if patched is None:
        pkg = re.escape(finding.package)
        # handles requirements.txt / package.json / gradle string-notation pins
        patched, n = re.subn(
            rf"({pkg}\s*[=:>~^ ]+)[0-9][\w.\-]*",
            rf"\g<1>{finding.fixed_version}",
            content, count=1,
        )
        if n == 0:
            return None

    if patched == content:
        return None
    return Patch(
        finding_fp=finding.fingerprint(), file_path=rel,
        original=content, patched=patched,
        rationale=f"Bump {finding.package} -> {finding.fixed_version} (fixes {finding.cve})",
        confidence=0.9,
    )


def remediate(repo_path: str, finding: Finding, test_cmd: str | None,
              max_attempts: int = 3) -> Patch | None:
    if not finding.auto_fixable:
        return None

    if finding.kind == FindingKind.DEPENDENCY:
        patch = _dependency_patch(repo_path, finding)
        if not patch:
            return None
        ok, evidence = validate_patch(repo_path, finding, patch.file_path, patch.patched, test_cmd)
        patch.validated, patch.validation_evidence = ok, evidence
        patch.confidence = 0.95 if ok else 0.4
        return patch

    # code / iac -> AI loop with validation feedback
    original = _read(repo_path, finding.file_path)
    if original is None:
        return None

    feedback = None
    for attempt in range(1, max_attempts + 1):
        result = _llm_patch(original, finding, feedback)
        if not result:
            return None
        patched, rationale = result
        if patched.strip() == original.strip():
            return None
        if _too_destructive(original, patched):
            feedback = ("previous candidate deleted most of the file; produce a "
                        "MINIMAL diff that preserves all unrelated code")
            continue
        ok, evidence = validate_patch(repo_path, finding, finding.file_path, patched, test_cmd)
        if ok:
            return Patch(
                finding_fp=finding.fingerprint(), file_path=finding.file_path,
                original=original, patched=patched, rationale=rationale,
                attempts=attempt, validated=True, validation_evidence=evidence,
                confidence=round(0.7 + 0.1 * len(finding.confirmed_by), 2),
            )
        feedback = " | ".join(evidence)

    # exhausted attempts: return best-effort unvalidated patch flagged for human review
    return Patch(
        finding_fp=finding.fingerprint(), file_path=finding.file_path,
        original=original, patched="", rationale="auto-fix could not be validated",
        attempts=max_attempts, validated=False,
        validation_evidence=[feedback or "no candidate"], confidence=0.0,
    )
