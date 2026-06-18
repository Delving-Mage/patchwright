from .base import Scanner
from .trivy import TrivyScanner
from .semgrep import SemgrepScanner
from .gitleaks import GitleaksScanner
from .osv import OsvScanner
from .checkov import CheckovScanner
from .bandit import BanditScanner
from .depcheck import DependencyCheckScanner

# Order is irrelevant (scan runs in parallel); coverage is what matters.
# Adding a scanner = drop a subclass in this dir + append it here. Nothing else
# in the pipeline changes.
ALL_SCANNERS = [
    TrivyScanner,
    SemgrepScanner,
    GitleaksScanner,
    OsvScanner,
    CheckovScanner,
    BanditScanner,
    DependencyCheckScanner,
]

# name -> class, so the validator can re-scan a finding with the EXACT scanner
# that produced it (fingerprints include rule_id, which is scanner-specific).
BY_NAME = {cls.name: cls for cls in ALL_SCANNERS}

__all__ = [
    "Scanner", "TrivyScanner", "SemgrepScanner", "GitleaksScanner",
    "OsvScanner", "CheckovScanner", "BanditScanner", "DependencyCheckScanner",
    "ALL_SCANNERS", "BY_NAME",
]
