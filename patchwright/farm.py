"""Two-way Farm integration -- the system-of-record loop, done better than the
incumbent (internal-tool + Snyk).

Your existing flow: tool reads a finding from the Farm API -> Snyk detects/fixes
-> results sync back to Farm. Patchwright runs the SAME loop, but outbeats it:

  1. RESOLVE / ENRICH  -- per finding INSTANCE, ask Farm for its farm-id + state
     (open / fixed / suppressed / accepted-risk / owner / SLA). We respect
     suppressed/accepted-risk so we don't re-litigate triaged items, and we
     reconcile against what Farm already knows.
  2. FIX (the edge)    -- our ensemble (7 scanners) + cross-file AI discovery
     finds vulns Snyk alone misses, and every fix is VALIDATED (re-scan + tests,
     or a PoC test for AI findings). We sync *proven* fixes, not suggestions.
  3. SYNC BACK         -- idempotent, evidence-rich state updates keyed by
     farm-id: FIXED_VALIDATED (with the re-scan/test/PoC proof + PR link),
     NEEDS_REVIEW, NEW (a finding Farm didn't have), or RESOLVED/REGRESSED from
     reconciliation. Re-running never duplicates.

Everything degrades gracefully: no FARM_API_URL, or any network/parse error, and
Patchwright runs exactly as before with empty farm fields. Farm is additive.

Config (env):
  FARM_API_URL          base URL (presence = enabled), e.g. https://farm.internal/api
  FARM_API_TOKEN        bearer token (or set FARM_API_HEADER for a custom header)
  FARM_API_HEADER       custom auth header name (value = FARM_API_TOKEN)
  FARM_RESOLVE_PATH     default "/findings/resolve"
  FARM_SYNC_PATH        default "/findings/sync"
  FARM_BATCH            batch size (default 200)
  FARM_SYNC_DRY_RUN     "1" -> log the sync payload instead of POSTing

API contract (adapt your endpoint or a thin shim to match):
  RESOLVE  POST {url}{resolve_path}
    body: {"findings": [{"key","fingerprint","file","line","rule_id","scanner",
                         "severity","cve","title"}]}
    resp: {"results": [{"key","farm_id","status","owner","sla_due", ...}]}
          (also accepts {"farm_ids": {key: farm_id}} or a bare list)
  SYNC     POST {url}{sync_path}
    body: {"updates": [{"farm_id","key","status","confidence","pr_url",
                        "evidence":[...], "patch_file"}]}
    resp: anything 2xx (ignored)
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

_SUPPRESSED_STATES = {"suppressed", "accepted_risk", "accepted-risk",
                      "wontfix", "won't_fix", "false_positive", "false-positive",
                      "ignored", "muted"}


class FarmClient:
    def __init__(self, base_url: str, token: str = "", header: str = "",
                 resolve_path: str = "/findings/resolve",
                 sync_path: str = "/findings/sync", batch: int = 200,
                 dry_run: bool = False, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.header = header
        self.resolve_path = resolve_path
        self.sync_path = sync_path
        self.batch = batch
        self.dry_run = dry_run
        self.timeout = timeout

    # ----- construction / availability ------------------------------------ #
    @classmethod
    def from_env(cls) -> "FarmClient | None":
        url = os.environ.get("FARM_API_URL")
        if not url:
            return None
        return cls(
            base_url=url,
            token=os.environ.get("FARM_API_TOKEN", ""),
            header=os.environ.get("FARM_API_HEADER", ""),
            resolve_path=os.environ.get("FARM_RESOLVE_PATH", "/findings/resolve"),
            sync_path=os.environ.get("FARM_SYNC_PATH", "/findings/sync"),
            batch=int(os.environ.get("FARM_BATCH", "200")),
            dry_run=os.environ.get("FARM_SYNC_DRY_RUN") == "1",
        )

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    # ----- low-level HTTP -------------------------------------------------- #
    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.token:
            if self.header:
                h[self.header] = self.token
            else:
                h["Authorization"] = f"Bearer {self.token}"
        return h

    def _post(self, path: str, payload: dict) -> dict | list | None:
        url = self.base_url + path
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers=self._headers())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
            return json.loads(body) if body else {}
        except Exception as e:  # noqa: BLE001 - never let Farm break a scan
            print(f"[farm] {path} failed: {e}", file=sys.stderr)
            return None

    # ----- (1) resolve + enrich ------------------------------------------- #
    @staticmethod
    def _finding_payload(f) -> dict:
        return {
            "key": f.fingerprint(),
            "fingerprint": f.fingerprint(),
            "file": f.file_path,
            "line": f.start_line,
            "rule_id": f.rule_id,
            "scanner": f.scanner,
            "severity": f.severity.name,
            "cve": f.cve,
            "title": f.title,
        }

    @staticmethod
    def _parse_results(resp) -> dict:
        """Normalize the various accepted response shapes into {key: record}."""
        out: dict[str, dict] = {}
        if resp is None:
            return out
        if isinstance(resp, dict) and "farm_ids" in resp:
            return {k: {"farm_id": v} for k, v in (resp["farm_ids"] or {}).items()}
        rows = resp.get("results") if isinstance(resp, dict) else resp
        for row in rows or []:
            if isinstance(row, dict) and row.get("key"):
                out[row["key"]] = row
        return out

    def resolve(self, findings: list) -> list:
        """Attach farm_id / farm_status / suppressed / farm_meta to each finding."""
        if not self.enabled or not findings:
            return findings
        for i in range(0, len(findings), self.batch):
            chunk = findings[i:i + self.batch]
            resp = self._post(self.resolve_path,
                              {"findings": [self._finding_payload(f) for f in chunk]})
            records = self._parse_results(resp)
            for f in chunk:
                rec = records.get(f.fingerprint())
                if not rec:
                    continue
                f.farm_id = str(rec.get("farm_id", "") or "")
                status = str(rec.get("status", "") or "")
                f.farm_status = status
                f.suppressed = status.lower() in _SUPPRESSED_STATES
                f.farm_meta = {k: v for k, v in rec.items()
                               if k not in ("farm_id", "status", "key")}
        return findings

    # ----- (3) sync back, with reconciliation ----------------------------- #
    def sync(self, report) -> dict:
        """Push proven results back to Farm. Idempotent (keyed by farm_id/key).

        Status per finding:
          FIXED_VALIDATED  -> a validated patch exists (proof attached)
          NEEDS_REVIEW     -> a patch was attempted but couldn't be proven
          NEW              -> Patchwright found it and Farm had no farm_id
          OPEN             -> known, still unfixed
        """
        if not self.enabled:
            return {"synced": 0, "skipped": "farm not configured"}

        fixed_fp = {p.finding_fp: p for p in report.validated_fixes}
        attempted_fp = {p.finding_fp for p in report.patches} - set(fixed_fp)
        pr_url = getattr(report, "pr_url", "") or ""

        updates = []
        for f in report.findings:
            fp = f.fingerprint()
            if f.suppressed:
                continue  # respect triage; don't re-open what Farm muted
            if fp in fixed_fp:
                p = fixed_fp[fp]
                status, evidence, conf = "FIXED_VALIDATED", p.validation_evidence, p.confidence
                patch_file = p.file_path
            elif fp in attempted_fp:
                status, evidence, conf, patch_file = "NEEDS_REVIEW", \
                    ["auto-fix attempted but not provable"], 0.0, ""
            elif not f.farm_id:
                status, evidence, conf, patch_file = "NEW", [f.discovery_note or f.title], 0.0, ""
            else:
                status, evidence, conf, patch_file = "OPEN", [], 0.0, ""
            updates.append({
                "farm_id": f.farm_id, "key": fp, "status": status,
                "confidence": conf, "pr_url": pr_url,
                "evidence": evidence, "patch_file": patch_file,
                "scanner": f.scanner, "severity": f.severity.name,
                "file": f.file_path, "line": f.start_line, "rule_id": f.rule_id,
            })

        if self.dry_run:
            print("[farm] DRY RUN sync payload:\n" +
                  json.dumps({"updates": updates}, indent=2))
            return {"synced": len(updates), "dry_run": True}

        sent = 0
        for i in range(0, len(updates), self.batch):
            resp = self._post(self.sync_path, {"updates": updates[i:i + self.batch]})
            if resp is not None:
                sent += len(updates[i:i + self.batch])
        return {"synced": sent, "total": len(updates)}
