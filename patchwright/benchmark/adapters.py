"""Load competitor tool output into the same lightweight finding-dict shape the
scorer understands, so Snyk (or anything that emits SARIF) is graded on the
EXACT same ground truth as Patchwright. That's the only fair head-to-head.

Each adapter returns a list of dicts: {file_path, start_line, rule_id, message}.
"""
from __future__ import annotations

import json


def load_snyk(path: str) -> list[dict]:
    """Snyk CLI JSON. Handles both `snyk code test --json` (SARIF-like) and
    `snyk test --json` (Open Source) shapes."""
    with open(path) as fh:
        data = json.load(fh)
    out: list[dict] = []

    # snyk code (SAST) emits SARIF under runs[].results[]
    if isinstance(data, dict) and "runs" in data:
        return load_sarif(path)

    # snyk open source: {"vulnerabilities": [{id, packageName, ...}]}
    blocks = data if isinstance(data, list) else [data]
    for block in blocks:
        for v in (block.get("vulnerabilities") or []):
            out.append({
                "file_path": block.get("displayTargetFile")
                or block.get("path") or "",
                "start_line": 0,
                "rule_id": v.get("identifiers", {}).get("CVE", [v.get("id")])[0]
                if isinstance(v.get("identifiers"), dict) else v.get("id", ""),
                "message": v.get("title", ""),
            })
    return out


def load_sarif(path: str) -> list[dict]:
    """Generic SARIF v2.1 (Snyk Code, Semgrep, CodeQL, etc.)."""
    with open(path) as fh:
        data = json.load(fh)
    out: list[dict] = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            loc = (res.get("locations") or [{}])[0]
            phys = loc.get("physicalLocation", {})
            out.append({
                "file_path": phys.get("artifactLocation", {}).get("uri", ""),
                "start_line": (phys.get("region", {}) or {}).get("startLine", 0) or 0,
                "rule_id": rid,
                "message": (res.get("message", {}) or {}).get("text", ""),
            })
    return out


# registry so the CLI can take --compare snyk:path.json / sarif:other.sarif
LOADERS = {
    "snyk": load_snyk,
    "sarif": load_sarif,
}


def load(spec: str) -> tuple[str, list[dict]]:
    """spec is 'kind:path' (e.g. 'snyk:snyk.json'). Returns (label, findings)."""
    kind, _, path = spec.partition(":")
    loader = LOADERS.get(kind.lower())
    if not loader:
        raise ValueError(f"unknown compare kind '{kind}'; known: {list(LOADERS)}")
    return kind, loader(path)
