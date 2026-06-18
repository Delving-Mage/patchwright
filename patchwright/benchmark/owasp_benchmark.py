"""Convert the OWASP Benchmark answer key into Patchwright ground-truth JSON.

OWASP Benchmark (https://github.com/OWASP-Benchmark/BenchmarkJava) is a Java/Spring
test suite of ~2,700 cases, each a known true- or false-positive for a CWE
category -- ideal ground truth for a recall/precision shootout on the target stack.

Its `expectedresults-*.csv` has columns:
  # test name, category, real vulnerability (true/false), cwe, ...

Usage:
  python -m patchwright.benchmark.owasp_benchmark expectedresults-1.2.csv gt.json \
      [--src-glob "src/main/java/org/owasp/benchmark/testcode/{name}.java"]
"""
from __future__ import annotations

import argparse
import csv
import json

# OWASP category slug -> our scorer category (see score._CATEGORY_KEYWORDS)
CATEGORY_MAP = {
    "sqli": "sqli",
    "xss": "xss",
    "cmdi": "cmdi",
    "pathtraver": "pathtraversal",
    "ldapi": "ldapi",
    "crypto": "crypto",
    "hash": "crypto",
    "weakrand": "crypto",
    "trustbound": "trustbound",
    "xpathi": "sqli",          # injection family
    "securecookie": "trustbound",
}


def convert(csv_path: str, name_template: str) -> dict:
    items = []
    with open(csv_path, newline="") as fh:
        # skip a leading comment line if present
        sample = fh.readline()
        fh.seek(0)
        if not sample.lower().startswith("# test name") and "," in sample:
            reader = csv.DictReader(fh)
        else:
            # header is commented; build our own field names
            fh.readline()
            reader = csv.DictReader(
                fh, fieldnames=["name", "category", "real", "cwe"])
        for row in reader:
            name = (row.get("name") or row.get("# test name") or "").strip()
            if not name:
                continue
            category = (row.get("category") or "").strip().lower()
            real = str(row.get("real", "")).strip().lower() in ("true", "1", "yes")
            items.append({
                "file": name_template.format(name=name),
                "category": CATEGORY_MAP.get(category, category),
                "label": real,
                "cwe": (row.get("cwe") or "").strip(),
            })
    return {"match": "category", "items": items}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="patchwright.benchmark.owasp_benchmark")
    ap.add_argument("csv_path")
    ap.add_argument("out_json")
    ap.add_argument("--name-template",
                    default="{name}.java",
                    help="how a test name maps to its source file (basename match "
                         "is enough for the scorer; default '{name}.java')")
    args = ap.parse_args(argv)
    gt = convert(args.csv_path, args.name_template)
    with open(args.out_json, "w") as fh:
        json.dump(gt, fh, indent=2)
    reals = sum(1 for i in gt["items"] if i["label"])
    print(f"wrote {args.out_json}: {len(gt['items'])} cases, {reals} real vulns")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
