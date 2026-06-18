"""Scoring math: synthetic ground truth + findings -> known precision/recall,
so the scorecard numbers are trustworthy."""
from patchwright.benchmark.score import GroundTruth, categorize, score


def test_categorize_maps_known_families():
    assert categorize("java.lang.security.sql-injection") == "sqli"
    assert categorize("python.flask.command-injection") == "cmdi"
    assert categorize("rule.about.weak-md5-hash") == "crypto"
    assert categorize("totally.unrelated.rule") is None


def _gt_location():
    return GroundTruth(match="location", line_tolerance=2, items=[
        {"file": "a.py", "line": 10, "label": True},
        {"file": "b.py", "line": 20, "label": True},
        {"file": "c.py", "line": 5, "label": False},
    ])


def test_location_scoring_tp_fp_fn():
    gt = _gt_location()
    findings = [
        {"file_path": "a.py", "start_line": 11, "rule_id": "x"},   # TP (within tol)
        {"file_path": "c.py", "start_line": 5, "rule_id": "x"},    # FP (safe spot)
        {"file_path": "a.py", "start_line": 50, "rule_id": "x"},   # FP (covered, unmatched)
    ]                                                              # b.py missed -> FN
    m = score("patchwright", findings, gt, fixed_proven=1)
    assert (m.tp, m.fp, m.fn) == (1, 2, 1)
    assert round(m.precision, 3) == 0.333
    assert m.recall == 0.5
    assert m.proven_fix_rate == 1.0          # 1 proven / 1 TP


def test_findings_outside_labelled_files_are_ignored():
    gt = _gt_location()
    findings = [
        {"file_path": "a.py", "start_line": 10, "rule_id": "x"},   # TP
        {"file_path": "z.py", "start_line": 99, "rule_id": "x"},   # outside scope -> ignored
    ]
    m = score("tool", findings, gt)
    assert (m.tp, m.fp) == (1, 0)


def test_category_mode_matches_on_vuln_class():
    gt = GroundTruth(match="category", items=[
        {"file": "Login.java", "category": "sqli", "label": True},
        {"file": "Safe.java", "category": "sqli", "label": False},
    ])
    findings = [
        {"file_path": "src/Login.java", "start_line": 0,
         "rule_id": "java.sql-injection.tainted"},               # TP via category
    ]
    m = score("tool", findings, gt)
    assert m.tp == 1 and m.fn == 0 and m.fp == 0
    assert m.recall == 1.0
