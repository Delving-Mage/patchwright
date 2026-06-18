# Beating Snyk — the benchmark workflow

You can't claim "outperforms Snyk" without numbers. This harness produces a
head-to-head scorecard on the **same ground truth**, scoring Patchwright and Snyk
(or any SARIF-emitting tool) on recall, precision, F1, and proven-fix-rate.

## The strategy (why this can win)

Snyk is **one** tuned engine. Patchwright is an **ensemble** — Trivy, OSV,
Dependency-Check, Semgrep, Bandit, Checkov, Gitleaks, plus AI discovery. On a
"find the most vulns" metric, the *union* of many engines can out-recall a single
engine. The validation + PoC loop is what stops that extra recall from turning
into false-positive noise, so you can lead on **recall** without wrecking
**precision** — and you uniquely report **proven** fixes.

Optimize for the three things the competition scores:
1. **Most found (recall):** run with `--discover deep`, stack Semgrep rulesets,
   install all scanner backends. More engines = more union coverage.
2. **Most fixed + proven:** pass `--test` so fixes are validated; PoC-confirmed
   AI findings and dep bumps count as proven.
3. **Accuracy vs ground truth:** the proof gate suppresses unproven findings, so
   precision stays competitive.

## 1. Get a ground-truth corpus (standard)

[OWASP BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) — ~2,700
labelled Java/Spring cases. Clone it, then convert its answer key:

```bash
python -m patchwright.benchmark.owasp_benchmark \
    BenchmarkJava/expectedresults-1.2.csv  owasp_gt.json
```

Other good targets: OWASP WebGoat, OWASP VulnerableApp, the Juliet Java suite.

## 2. Write ground truth for YOUR target repo

A small JSON answer key (`match: location` is easiest):

```json
{
  "match": "location",
  "line_tolerance": 2,
  "items": [
    {"file": "src/main/java/com/acme/Login.java", "line": 88, "label": true,  "category": "sqli"},
    {"file": "src/main/java/com/acme/Health.java", "line": 12, "label": false}
  ]
}
```

`label: true` = a real vuln the tool should catch; `label: false` = a safe spot a
noisy tool would wrongly flag (drives precision).

## 3. Produce competitor numbers on the same repo

```bash
# Snyk SAST (SARIF) and/or Snyk Open Source (JSON)
snyk code test --sarif-file-output=snyk-code.sarif ./target-repo
snyk test --json > snyk-oss.json
```

## 4. Run the head-to-head scorecard

```bash
python -m patchwright.benchmark run \
    --repo ./target-repo \
    --truth owasp_gt.json \
    --test "mvn -q -DskipTests=false test" \
    --discover deep \
    --compare snyk:snyk-code.sarif \
    --compare snyk:snyk-oss.json \
    --out scorecard
```

Outputs `scorecard.md` (the table to show judges) and `scorecard.json`. Rows are
sorted by **Youden's J (TPR − FPR)** — the OWASP Benchmark headline metric — then
recall, then F1. The table also reports precision, FPR, F1, and proven-fix-rate.

**You win when Patchwright leads recall AND proven-fix-rate at comparable
precision.** If precision lags, raise the AI-discovery confidence floor
(`PW_DISCOVER_*`) or rely more on PoC-confirmed findings; if recall lags, add
scanners / `--discover deep` / more Semgrep rulesets (`PW_SEMGREP_CONFIG`).

## Honest caveat

On per-vuln detection *accuracy* for common CWEs, Snyk's tuned engine is strong;
expect a real fight on precision. Patchwright's edge is **ensemble recall +
verifiable proof + zero cost/lock-in**. Pick the metric where that wins, and let
the scorecard make the case for you.
