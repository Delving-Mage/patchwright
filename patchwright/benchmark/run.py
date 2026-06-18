"""Benchmark CLI -- the scorecard that proves (or disproves) "beats Snyk".

    python -m patchwright.benchmark run \
        --repo ./vulnerable-app \
        --truth ground_truth.json \
        --test "mvn -q test" \
        --compare snyk:snyk-code.sarif \
        --out scorecard

Runs the full Patchwright pipeline on the repo, scores it against the ground
truth, scores every --compare tool on the SAME ground truth, and writes a
head-to-head markdown table + JSON. Higher recall + higher proven-fix-rate at
comparable precision = you win.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import pipeline
from . import adapters
from .score import GroundTruth, Metrics, score


def _patchwright_metrics(repo: str, gt: GroundTruth, test_cmd: str | None,
                         discover_mode: str) -> tuple[Metrics, dict]:
    # sync=False: never write to the Farm system-of-record during benchmarking
    report = pipeline.run(repo, test_cmd=test_cmd, fix=True,
                          discover_mode=discover_mode, sync=False)
    proven = len(report.validated_fixes)
    m = score("patchwright", report.findings, gt, fixed_proven=proven)
    return m, report.summary()


def _table(rows: list[Metrics]) -> str:
    head = ("| Tool | Reported | TP | FP | FN | Precision | Recall | FPR "
            "| Youden (TPR-FPR) | F1 | Proven fixes | Proven-fix rate |")
    sep = ("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: "
           "| ---: | ---: |")
    lines = [head, sep]
    for m in rows:
        lines.append(
            f"| {m.tool} | {m.reported} | {m.tp} | {m.fp} | {m.fn} "
            f"| {m.precision:.0%} | **{m.recall:.0%}** | {m.fpr:.0%} "
            f"| **{m.youden:.2f}** | {m.f1:.2f} "
            f"| {m.fixed_proven} | {m.proven_fix_rate:.0%} |")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="patchwright.benchmark")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run + score a head-to-head benchmark")
    r.add_argument("--repo", required=True)
    r.add_argument("--truth", required=True, help="ground-truth JSON")
    r.add_argument("--test", default=None, help="test command for proven fixes")
    r.add_argument("--discover", default="augment", choices=["off", "augment", "deep"])
    r.add_argument("--compare", action="append", default=[],
                   help="competitor results as kind:path (e.g. snyk:out.sarif). Repeatable.")
    r.add_argument("--out", default="scorecard", help="output basename (.md + .json)")
    args = ap.parse_args(argv)

    gt = GroundTruth.load(args.truth)
    rows: list[Metrics] = []

    pw, summary = _patchwright_metrics(args.repo, gt, args.test, args.discover)
    rows.append(pw)

    for spec in args.compare:
        try:
            label, findings = adapters.load(spec)
        except (ValueError, OSError, json.JSONDecodeError) as e:
            print(f"skip --compare {spec}: {e}", file=sys.stderr)
            continue
        rows.append(score(label, findings, gt))

    rows.sort(key=lambda m: (m.youden, m.recall, m.f1), reverse=True)
    table = _table(rows)

    md = [
        "# Patchwright benchmark scorecard",
        "",
        f"Repo: `{args.repo}`  •  ground-truth reals: **{len(gt.reals)}**"
        f"  •  match mode: `{gt.match}`",
        "",
        table,
        "",
        f"_Patchwright scanners used: {', '.join(summary.get('scanners', []))}_",
        f"_AI-discovery: {summary.get('ai_discovered', 0)} surfaced, "
        f"{summary.get('ai_confirmed_by_poc', 0)} PoC-confirmed._",
    ]
    md_text = "\n".join(md)

    with open(f"{args.out}.md", "w") as fh:
        fh.write(md_text + "\n")
    with open(f"{args.out}.json", "w") as fh:
        json.dump({"ground_truth_reals": len(gt.reals),
                   "match": gt.match,
                   "patchwright_summary": summary,
                   "results": [m.to_dict() for m in rows]}, fh, indent=2)

    print(md_text)
    print(f"\nwrote {args.out}.md and {args.out}.json")
    winner = rows[0]
    print(f"\nTop recall: {winner.tool} ({winner.recall:.0%}). "
          "Patchwright wins if it leads recall + proven-fix-rate at comparable precision.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
