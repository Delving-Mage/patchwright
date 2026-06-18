"""Scanner adapters. Each one shells out to a best-in-class OSS scanner and
maps its native output into our canonical Finding list. Adding a new scanner =
one subclass; the rest of the pipeline is untouched."""
from __future__ import annotations

import json
import shutil
import subprocess
from abc import ABC, abstractmethod

from ..models import Finding


class Scanner(ABC):
    name: str = "base"
    binary: str = ""

    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def _run(self, args: list[str], cwd: str) -> str:
        proc = subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, timeout=900
        )
        # most scanners exit non-zero when they FIND issues; that's not an error
        return proc.stdout

    @abstractmethod
    def scan(self, repo_path: str) -> list[Finding]:
        ...
