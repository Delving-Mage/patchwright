"""Contextual prioritization.

Most tools sort by raw CVSS. That floods you with "critical" deps you never call.
We compute a CONTEXTUAL score so the fix engine spends effort where it matters:

    score = base_severity
          * reachability_factor   (is the vulnerable package actually imported?)
          * confirmation_factor   (how many scanners independently agree?)
          * fixability_factor     (a clean fix exists => act now)
          + secret_in_history_boost

Reachability is a cheap static heuristic (grep the import/usage), not full call-graph
analysis -- but it removes most of the noise that makes triage miserable."""
from __future__ import annotations

import os
import re

from .models import Finding, FindingKind, Severity


def _reachability_needles(package: str) -> re.Pattern:
    """Build a regex of plausible source tokens for a package, per ecosystem.

    The whole point is to answer "does this repo actually USE the vulnerable
    package?" so an unused transitive dep ranks below reachable code. The token
    that proves usage differs by language:

      * Maven/Gradle ('groupId:artifactId'): Java/Kotlin code imports the
        *groupId* namespace (e.g. 'import org.apache.commons...'), NOT the
        artifactId. So we search for the groupId as an import prefix AND the
        artifactId as a fallback.
      * npm scoped ('@scope/name') / pip / others: the last path/colon segment
        is the import name.
    """
    tokens: set[str] = set()
    if ":" in package and "/" not in package:        # Maven/Gradle coordinate
        group_id, _, artifact_id = package.partition(":")
        if group_id:
            tokens.add(group_id)                     # dotted import namespace
        if artifact_id:
            tokens.add(artifact_id)
            tokens.add(artifact_id.replace("-", ""))  # commons-lang -> commonslang
    else:
        base = package.split(":")[-1].split("/")[-1]
        tokens.add(base)
        tokens.add(base.replace("-", "_"))           # py: foo-bar -> foo_bar
    tokens = {t for t in tokens if len(t) >= 3}      # avoid 1-2 char false hits
    if not tokens:
        return re.compile(r"(?!)")                   # matches nothing
    return re.compile("|".join(re.escape(t) for t in sorted(tokens)), re.IGNORECASE)


def _package_imported(repo_path: str, package: str) -> bool:
    if not package:
        return True
    needle = _reachability_needles(package)
    exts = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".scala",
            ".go", ".rb", ".groovy")
    for root, _dirs, files in os.walk(repo_path):
        if any(skip in root for skip in (".git", "node_modules", "venv",
                                         "dist", "build", "target", ".gradle")):
            continue
        for fn in files:
            if fn.endswith(exts):
                try:
                    with open(os.path.join(root, fn), errors="ignore") as fh:
                        if needle.search(fh.read()):
                            return True
                except OSError:
                    continue
    return False


def score(findings: list[Finding], repo_path: str) -> list[Finding]:
    for f in findings:
        base = float(f.cvss) if f.cvss else float(f.severity) * 2.5  # ~0..10

        if f.kind == FindingKind.DEPENDENCY:
            reachable = _package_imported(repo_path, f.package or "")
            f.reachable = reachable
            reach_factor = 1.0 if reachable else 0.35
        else:
            f.reachable = True
            reach_factor = 1.0

        # each INDEPENDENT scanner that agrees adds 15%; a lone finding is neutral
        # (never penalized -- the old `len-1` under-counted single-scanner hits).
        agree = max(0, len(set(f.confirmed_by)) - 1)
        confirm_factor = 1.0 + 0.15 * agree
        fix_factor = 1.15 if f.auto_fixable else 1.0
        secret_boost = 4.0 if f.kind == FindingKind.SECRET else 0.0

        f.risk_score = round(base * reach_factor * confirm_factor * fix_factor + secret_boost, 2)

    findings.sort(key=lambda x: x.risk_score, reverse=True)
    return findings
