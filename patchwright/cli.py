"""patchwright CLI.

  patchwright scan   PATH                 # detect + prioritize, no changes
  patchwright fix    PATH [--test CMD]    # detect + validated auto-fix
  patchwright apply  PATH                 # write validated patches to disk
  patchwright pr     PATH [--base main]   # bundle validated fixes into ONE Bitbucket PR
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import pipeline


def _print_table(report) -> None:
    print(f"\n  scanners: {', '.join(report.scanners_used) or 'NONE (install trivy/semgrep/gitleaks)'}")
    print(f"  {'RISK':>6}  {'SEV':<8} {'KIND':<11} {'FIX':<10} LOCATION")
    print("  " + "-" * 72)
    for f in report.findings[:40]:
        patch = next((p for p in report.patches if p.finding_fp == f.fingerprint()), None)
        if patch and patch.validated:
            fix = "✓ FIXED"
        elif patch:
            fix = "needs rev"
        elif f.auto_fixable:
            fix = "fixable"
        else:
            fix = "-"
        loc = f"{f.file_path}:{f.start_line}" if f.start_line else f.file_path
        if f.scanner == "ai-discovery":
            loc += "  [AI✓ PoC]" if f.confirmed else "  [AI? suspected]"
        if f.suppressed:
            loc += "  [farm:suppressed]"
        elif f.farm_id:
            loc += f"  [{f.farm_id}]"
        print(f"  {f.risk_score:>6}  {f.severity.name:<8} {f.kind.name:<11} {fix:<10} {loc[:80]}")


def _pr_body(report) -> str:
    lines = ["## 🛡️ Patchwright — validated security fixes\n",
             f"Auto-fixed **{len(report.validated_fixes)}** vulnerabilities "
             f"(scanner-reverified + tests passed).\n"]
    for p in report.validated_fixes:
        lines.append(f"- **{p.file_path}** — {p.rationale} "
                     f"_(confidence {p.confidence:.0%}, {p.attempts} attempt(s))_")
        for e in p.validation_evidence:
            lines.append(f"  - ✓ {e}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="patchwright")
    ap.add_argument("command", choices=["scan", "fix", "apply", "pr"])
    ap.add_argument("path")
    ap.add_argument("--test", default=os.environ.get("PW_TEST_CMD"),
                    help="test command the patch must keep green, e.g. 'pytest -q'")
    ap.add_argument("--json", action="store_true", help="emit machine-readable report")
    ap.add_argument("--base", default=os.environ.get("PW_BASE_BRANCH", "main"),
                    help="target branch for the PR (default: main)")
    ap.add_argument("--dry-run", action="store_true",
                    help="pr: commit to a local branch and print the PR body, no push")
    ap.add_argument("--discover", default=os.environ.get("PW_AI_DISCOVERY", "augment"),
                    choices=["off", "augment", "deep"],
                    help="AI vuln discovery: off | augment (flagged files) | deep "
                         "(full sweep). Needs ANTHROPIC_API_KEY.")
    ap.add_argument("--no-sync", action="store_true",
                    help="do not sync results back to the Farm system-of-record")
    ap.add_argument("--fail-on", default="HIGH",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                    help="exit non-zero if an UNFIXED finding >= this severity remains")
    args = ap.parse_args(argv)

    do_fix = args.command in ("fix", "apply", "pr")
    # for `pr` we defer the farm sync until AFTER the PR is opened, so the synced
    # FIXED_VALIDATED records carry the PR URL.
    sync_now = not args.no_sync and args.command != "pr"
    report = pipeline.run(args.path, test_cmd=args.test, fix=do_fix,
                          discover_mode=args.discover, sync=sync_now)

    if args.command == "apply":
        for p in report.validated_fixes:
            with open(os.path.join(args.path, p.file_path), "w") as fh:
                fh.write(p.patched)
        print(f"applied {len(report.validated_fixes)} validated patches to disk")

    if args.command == "pr":
        from . import bitbucket
        res = bitbucket.open_pr(args.path, report, base_branch=args.base,
                                dry_run=args.dry_run)
        print(f"\nbranch: {res.branch}\ntitle:  {res.title}")
        print(f"status: {res.detail}")
        if res.url:
            print(f"PR:     {res.url}")
        if args.dry_run or not res.created:
            print("\n--- PR body ---\n" + res.body)
        # now sync to farm with the PR URL attached
        if not args.no_sync:
            from .farm import FarmClient
            client = FarmClient.from_env()
            if client and client.enabled:
                report.pr_url = res.url or ""
                report.farm_sync = client.sync(report)

    if args.json:
        print(json.dumps({
            "summary": report.summary(),
            "findings": [f.to_dict() for f in report.findings],
        }, indent=2))
    else:
        _print_table(report)
        s = report.summary()
        print(f"\n  {s['total_findings']} findings | "
              f"{s['auto_fixed_validated']} validated fixes | "
              f"{s['needs_review']} need review")
        if s.get("ai_discovered"):
            print(f"  AI-discovery: {s['ai_discovered']} surfaced, "
                  f"{s['ai_confirmed_by_poc']} confirmed by PoC test")
        if s.get("farm_resolved") or s.get("farm_suppressed"):
            print(f"  Farm: {s['farm_resolved']} resolved to farm-ids, "
                  f"{s['farm_suppressed']} suppressed")
        if s.get("farm_sync"):
            fs = s["farm_sync"]
            print(f"  Farm sync: {fs.get('synced', 0)} updates"
                  + (" (dry-run)" if fs.get("dry_run") else ""))
        if report.validated_fixes:
            print("\n" + _pr_body(report))

    # CI gate
    if args.fail_on != "NONE":
        from .models import Severity
        gate = Severity.parse(args.fail_on)
        fixed_fps = {p.finding_fp for p in report.validated_fixes}
        remaining = [f for f in report.findings
                     if f.severity >= gate and f.fingerprint() not in fixed_fps]
        if remaining:
            print(f"\n✗ gate: {len(remaining)} unfixed finding(s) >= {args.fail_on}", file=sys.stderr)
            return 1
    print("\n✓ gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
