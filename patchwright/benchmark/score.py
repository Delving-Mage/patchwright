"""Scoring core: compare a list of findings against a ground-truth answer key
and compute the metrics the competition is judged on.

Ground-truth file (JSON):
{
  "match": "location",                 # "location" | "category"
  "line_tolerance": 2,                  # location mode: +/- lines that still count
  "items": [
    {"file": "src/Login.java", "line": 42, "category": "sqli", "label": true},
    {"file": "src/Safe.java",  "line": 10, "category": "sqli", "label": false},
    ...
  ]
}

- label=true  -> a REAL vulnerability the tool SHOULD report (true positive if found)
- label=false -> a safe spot a noisy tool might wrongly flag (false positive if found)

location mode: a finding matches an item if same file (basename) and |line - item.line|
<= tolerance. category mode: same file (basename) and same category (good for
corpora like OWASP Benchmark that label per test case + CWE category).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

# Map a tool's rule_id / cve to a coarse vuln category so heterogeneous engines
# can be compared on the same category-labelled ground truth. Extend freely.
_CATEGORY_KEYWORDS = {
    "sqli": ("sql", "sqli", "sql-injection", "sqlinjection"),
    "xss": ("xss", "cross-site-scripting", "cross_site"),
    "cmdi": ("command-injection", "command_injection", "os-command", "rce", "shell"),
    "pathtraversal": ("path-traversal", "pathtraversal", "directory-traversal", "zipslip"),
    "ssrf": ("ssrf", "server-side-request"),
    "deserialization": ("deserial", "insecure-deserialization", "pickle"),
    "crypto": ("crypto", "weak-hash", "md5", "sha1", "cipher", "insecure-random", "weak-ssl"),
    "xxe": ("xxe", "xml-external", "xmlexternal"),
    "ldapi": ("ldap-injection", "ldapi"),
    "trustbound": ("trust-boundary", "trustbound"),
    "secret": ("secret", "hardcoded", "api-key", "password"),
}


def categorize(rule_id: str, message: str = "") -> str | None:
    hay = f"{rule_id} {message}".lower()
    for cat, kws in _CATEGORY_KEYWORDS.items():
        if any(k in hay for k in kws):
            return cat
    return None


@dataclass
class Metrics:
    tool: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0                # safe spots correctly NOT flagged (for FPR/Youden)
    reported: int = 0          # total findings the tool produced (pre-matching)
    fixed_proven: int = 0      # validated/proven fixes (Patchwright only)
    real_total: int = 0        # ground-truth real vulns (denominator for recall)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:                 # == TPR
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def fpr(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def youden(self) -> float:
        """OWASP Benchmark score = TPR - FPR. A blind guesser sits at 0; this is
        the number OWASP-aware judges look for."""
        return self.recall - self.fpr

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def proven_fix_rate(self) -> float:
        return self.fixed_proven / self.tp if self.tp else 0.0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool, "reported": self.reported,
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "fpr": round(self.fpr, 3),
            "youden": round(self.youden, 3),
            "f1": round(self.f1, 3),
            "fixed_proven": self.fixed_proven,
            "proven_fix_rate": round(self.proven_fix_rate, 3),
        }


@dataclass
class GroundTruth:
    match: str = "location"
    line_tolerance: int = 2
    items: list[dict] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "GroundTruth":
        with open(path) as fh:
            data = json.load(fh)
        return cls(
            match=data.get("match", "location"),
            line_tolerance=int(data.get("line_tolerance", 2)),
            items=data.get("items", []),
        )

    @property
    def reals(self) -> list[dict]:
        return [i for i in self.items if i.get("label", True)]


def _base(path: str) -> str:
    return os.path.basename(path or "")


def _finding_view(f) -> dict:
    """Accept either a Patchwright Finding or a plain dict (from adapters)."""
    if isinstance(f, dict):
        rid = f.get("rule_id", "")
        return {
            "file": f.get("file_path", ""), "line": int(f.get("start_line", 0) or 0),
            "rule_id": rid, "message": f.get("message", ""),
            "category": f.get("category") or categorize(rid, f.get("message", "")),
        }
    return {
        "file": getattr(f, "file_path", ""), "line": int(getattr(f, "start_line", 0) or 0),
        "rule_id": getattr(f, "rule_id", ""), "message": getattr(f, "message", ""),
        "category": categorize(getattr(f, "rule_id", ""), getattr(f, "message", "")),
    }


def _matches(view: dict, item: dict, gt: GroundTruth) -> bool:
    if _base(view["file"]) != _base(item.get("file", "")):
        return False
    if gt.match == "category":
        return bool(view["category"]) and view["category"] == item.get("category")
    # location
    if not item.get("line"):
        return True
    return abs(view["line"] - int(item["line"])) <= gt.line_tolerance


def score(tool: str, findings: list, gt: GroundTruth,
          fixed_proven: int = 0) -> Metrics:
    """Score one tool's findings against the ground truth.

    Each ground-truth item is counted once: a real item with >=1 matching finding
    is a TP (else FN); a safe (label=false) item with a matching finding is an FP.
    Findings that match no ground-truth item at all are also counted as FP only if
    they fall in a file the answer key covers (so we don't penalize a tool for
    findings outside the labelled scope)."""
    views = [_finding_view(f) for f in findings]
    m = Metrics(tool=tool, reported=len(views), fixed_proven=fixed_proven)
    m.real_total = len(gt.reals)

    covered_files = {_base(i.get("file", "")) for i in gt.items}
    matched_view_idx: set[int] = set()

    for item in gt.items:
        hit = None
        for idx, v in enumerate(views):
            if _matches(v, item, gt):
                hit = idx
                break
        if item.get("label", True):           # real vuln
            if hit is not None:
                m.tp += 1
                matched_view_idx.add(hit)
            else:
                m.fn += 1
        else:                                  # safe spot
            if hit is not None:
                m.fp += 1
                matched_view_idx.add(hit)
            else:
                m.tn += 1                      # correctly left alone

    # In LOCATION mode, extra findings inside labelled files that matched nothing
    # are false positives. In CATEGORY mode (e.g. OWASP Benchmark) scoring is per
    # labelled test case, so we don't invent FPs from unlabelled lines.
    if gt.match == "location":
        for idx, v in enumerate(views):
            if idx in matched_view_idx:
                continue
            if _base(v["file"]) in covered_files:
                m.fp += 1
    return m
