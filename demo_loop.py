"""Prove the closed validation loop without needing an API key, by stubbing the
LLM with (a) a correct fix and (b) a fix that removes the vuln but breaks tests.
The real Semgrep re-scan and the real pytest run are the judges."""
import os
os.environ["PW_SEMGREP_CONFIG"] = "/tmp/vuln_repo/.pw-rules.yaml"

from patchwright import pipeline, remediate
from patchwright.remediate import remediate as run_remediate

REPO = "/tmp/vuln_repo"
TEST = "python3 -m pytest -q"

GOOD_FIX = '''import subprocess
import ast

def run_lookup(hostname):
    return subprocess.call(["nslookup", hostname])

def calc(expr):
    return ast.literal_eval(expr)

API_TOKEN = "hardcoded-secret-do-not-ship"
'''

BROKEN_FIX = '''import subprocess
import ast

def run_lookup(hostname):
    return subprocess.call(["nslookup", hostname])

def calc(expr):
    return None  # removes eval but silently breaks behavior

API_TOKEN = "hardcoded-secret-do-not-ship"
'''

# get a real finding from the live scanner
report = pipeline.run(REPO, fix=False)
eval_finding = next(f for f in report.findings if f.start_line == 9)
print(f"target finding: {eval_finding.rule_id} @ {eval_finding.file_path}:{eval_finding.start_line}\n")

def trial(label, fixed_content):
    remediate._llm_patch = lambda fc, finding, feedback: (fixed_content, f"{label} candidate")
    patch = run_remediate(REPO, eval_finding, test_cmd=TEST, max_attempts=1)
    verdict = "ACCEPTED ✓" if (patch and patch.validated) else "REJECTED ✗"
    print(f"[{label}]  -> {verdict}")
    if patch:
        for e in patch.validation_evidence:
            print(f"        • {e}")
    print()

trial("GOOD-FIX", GOOD_FIX)
trial("BROKEN-FIX", BROKEN_FIX)
