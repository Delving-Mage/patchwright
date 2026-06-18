# HANDOFF — Patchwright

Drop this whole folder into Cowork or Claude Code and start from this file.
It captures everything decided and verified so far so you don't re-derive context.

## What this is
**Patchwright** — closed-loop, *validated* AI vulnerability remediation for a
Bitbucket repo, built to win a "find + fix the most vulns" competition.

The differentiator (the whole pitch): existing tools stop at *suggesting* fixes.
Patchwright applies each candidate patch in a sandbox, **re-runs the same scanner
on the same finding to prove the vuln is gone, AND runs the project's test suite to
prove nothing broke** — only then is the patch accepted. The model never grades its
own work; the scanner + tests are the judge. That's what allows auto-merge instead
of nagging a human.

## Verified working (run on a live scanner in the build session)
- Real **Semgrep** detection -> SARIF parse -> canonical `Finding` model. ✓
- Multi-scanner **fan-in + dedup + cross-confirmation** (same vuln from 2 scanners
  becomes 1 finding with higher trust). ✓
- **Contextual prioritization**: a CVSS-10 dependency that isn't imported ranks
  *below* a reachable HIGH code finding (reachability downweight). ✓
- **Validation loop, both directions**:
  - good fix (eval -> ast.literal_eval) -> re-scan clean + tests pass -> **ACCEPTED**
  - broken fix (removes eval but returns None) -> re-scan clean but **tests FAIL**
    -> **REJECTED**. A scanner-only autofixer would have shipped that broken patch.
- **Sandbox isolation** confirmed (real repo file untouched during validation). ✓

## Two real bugs already fixed (don't reintroduce)
1. **Sandbox escape**: scanners emit *absolute* paths; `os.path.join(sandbox, "/abs")`
   silently drops the sandbox root, so patches hit the real repo while the re-scan
   checked an untouched copy. Fixed by normalizing all finding paths to repo-relative
   in `pipeline.run` + a guard in `validate.validate_patch`.
2. **Fingerprint misalignment**: re-scan residuals carried sandbox-absolute paths,
   so the "is the finding gone?" comparison failed. Fixed by relativizing residual
   paths in `validate._rescan_file` before comparing fingerprints.

## Architecture (one job per file)
- `models.py` — canonical `Finding`/`Patch`, severity, fingerprinting, auto_fixable.
- `scanners/` — one adapter per OSS scanner: **trivy, osv-scanner, semgrep, bandit,
  checkov, gitleaks**. Add a scanner = one subclass + register in
  `scanners/__init__.py` (which also exports `BY_NAME`). Nothing else changes.
- `normalize.py` — merge + cross-scanner confirmation (dep findings keyed on CVE).
- `prioritize.py` — contextual risk score (reachability/confirmation/fixability).
  Reachability is ecosystem-aware: Maven coords resolve to the groupId import
  namespace, not the artifactId.
- `validate.py` — sandbox copy -> re-scan finding **with the exact scanner that
  found it** (`_scanner_for_finding`) -> run tests -> accept/reject.
- `remediate.py` — deterministic dep-bump fixer (incl. XML-aware Maven `pom.xml`
  literal + `${property}` pinning) + AI code-fix loop with retry-on-validation-
  failure. AI path calls the Anthropic messages API (needs ANTHROPIC_API_KEY).
- `bitbucket.py` — bundle validated patches into ONE PR with an evidence-table
  body; git+REST API, `--dry-run` works offline.
- `llm.py` — shared stdlib Anthropic Messages client (`complete` / `complete_json`).
- `discover.py` — AI-discovery engine (Mythos-inspired, defensive). Reasons over
  source for flaws the rule engines miss; writes a PoC test that FAILS on the
  vulnerable code to CONFIRM the vuln. Modes: off | augment (flagged files) | deep.
- `pipeline.py` — orchestrates scan -> merge -> AI discovery -> prioritize -> remediate.
- `cli.py` — `scan` / `fix` / `apply` / `pr`, `--discover`, JSON report, CI gate.
- `tests/` — normalize/prioritize/validate/remediate/discover (`pip install -e ".[dev]"; pytest`).

## AI discovery — design notes (the Mythos-style differentiator)
- Two tiers: CONFIRMED (PoC test reproduced the vuln) vs AI-SUSPECTED (unproven).
  Only CONFIRMED findings are auto-fixed/merged; suspected ones go to human review.
- AI findings carry `poc_test` + `poc_test_rel` on the `Finding`. `validate.py`
  routes scanner=="ai-discovery" to `_validate_ai_finding`: the fix is accepted
  only when the PoC (which failed on vulnerable code) now PASSES and tests stay green.
- PoC confirmation is Python/pytest-only today; other languages stay "suspected".
- Strictly defensive: the model writes tests asserting secure behavior, never
  exploits/payloads. Honest framing in README: this is NOT Claude Mythos.

## How to run
```bash
pip install -e .
pip install semgrep                      # + trivy, gitleaks binaries as desired
export ANTHROPIC_API_KEY=sk-...          # enables AI code fixes (dep fixes work without it)

patchwright scan  ./repo                          # add --discover deep for full AI sweep
patchwright fix   ./repo --test "pytest -q"       # --discover augment is the default
patchwright apply ./repo --test "pytest -q"       # writes validated patches to disk
patchwright pr    ./repo --base main --dry-run    # bundle validated fixes into one PR
```
Offline / custom Semgrep rules: `export PW_SEMGREP_CONFIG=/path/to/rules.yaml`.
AI discovery knobs: `PW_AI_DISCOVERY` (off|augment|deep), `PW_DISCOVER_MAX_FILES`,
`PW_DISCOVER_MAX_BYTES`, `PW_MODEL`.

## Reproduce the loop proof
`demo_loop.py` stubs the LLM with a good and a broken fix and runs the REAL
validator (real Semgrep re-scan + real pytest). Expected: GOOD accepted, BROKEN
rejected. Needs a vulnerable sample repo at /tmp/vuln_repo (see README for the
3 files: app.py with eval+shell=True, test_app.py, .pw-rules.yaml).

## Done since last handoff
- [x] `osv-scanner`, `checkov`, `bandit` adapters added + registered (more coverage
      + cross-confirmation). Validator now re-scans with the finding's own scanner.
- [x] Reachability upgrade: Maven groupId import-namespace heuristic (Java/Kotlin/
      Groovy/Scala extensions added; `target`/`.gradle` excluded).
- [x] Maven `pom.xml` deterministic dep-fix (literal + `${property}` forms), tempered
      regex isolates the correct `<dependency>` block.
- [x] `patchwright pr`: groups validated patches into ONE Bitbucket PR with an
      evidence table; `bitbucket-pipelines.yml` rewritten to use it + new scanners.
- [x] Unit tests for normalize/prioritize/validate/remediate.
- [x] AI-discovery layer (`llm.py` + `discover.py`): augment/deep modes, PoC-test
      confirmation, two-tier (confirmed/suspected), wired into pipeline + CLI
      `--discover` + report. Tests in `tests/test_discover.py`.
- [x] **Benchmark harness** (`patchwright/benchmark/`): scores Patchwright AND Snyk
      (or any SARIF) on the SAME ground truth -> recall/precision/F1/proven-fix-rate
      scorecard. OWASP Benchmark CSV converter. `tests/test_benchmark.py`.
- [x] `dependency-check` scanner added (third SCA engine, Java recall boost).
- [x] **Depth pass** ("think deeper"): cross-file taint-aware discovery
      (`context.py` + `_XFILE_PROMPT`; deep mode traces source->sink across files);
      location-based cross-engine consensus (`normalize.cross_confirm_by_location`)
      that boosts trust without merging away findings; confirm_factor floor bug fixed.
- [x] **Fix-safety**: `validate.syntax_ok` pre-gate (parse before paying for sandbox
      + tests) and `remediate._too_destructive` guard against whole-file rewrites.
- [x] **Scorer credibility**: TN tracking + FPR + Youden's J (TPR-FPR), the OWASP
      Benchmark metric; extra-FP rule gated to location mode. Tests in test_strength.py.
- [x] **Farm system-of-record integration** (`farm.py`): two-way client mirroring
      the org loop (internal tool + Snyk) but beating it. RESOLVE/enrich per finding
      instance (farm_id + status + suppression, keyed by fingerprint); respects
      suppressed/accepted-risk; SYNC back idempotent + evidence-rich
      (FIXED_VALIDATED with proof+PR / NEEDS_REVIEW / NEW / OPEN). Finding gains
      farm_id/farm_status/suppressed/farm_meta. Wired into pipeline (resolve after
      prioritize, sync after fix; `pr` syncs post-PR so the URL is attached), CLI
      (`--no-sync`, table + summary), PR evidence table. Env contract documented in
      farm.py header. Tests in `tests/test_farm.py`.
- [x] Outbeat framing: we sync PROVEN fixes (not Snyk's suggestions), report vulns
      Snyk misses as NEW, and reconcile (close resolved / reopen regressions).

## Farm API contract (point your endpoint or a shim at this)
- RESOLVE POST {FARM_API_URL}{FARM_RESOLVE_PATH=/findings/resolve}
    body {"findings":[{key,fingerprint,file,line,rule_id,scanner,severity,cve,title}]}
    resp {"results":[{key,farm_id,status,...}]} (also accepts {"farm_ids":{key:id}} or bare list)
- SYNC    POST {FARM_API_URL}{FARM_SYNC_PATH=/findings/sync}
    body {"updates":[{farm_id,key,status,confidence,pr_url,evidence,patch_file,...}]}
- Auth: Bearer FARM_API_TOKEN, or custom header name via FARM_API_HEADER.
- `key` is Patchwright's per-instance fingerprint (stable across runs).

## Competitive reality vs Snyk (read before pitching)
- Snyk Agent Fix (2026) ALSO does sandboxed validate-and-iterate fixes, so the
  "validated remediation" pitch is no longer unique. The README table was rewritten
  to be honest. Do NOT show the old "Snyk ✗ everything" table to informed judges.
- Winnable axis = ENSEMBLE RECALL (union of 7 scanners + AI) + PROVEN-FIX-RATE +
  open/zero-cost/self-hosted. Snyk still likely wins per-vuln accuracy on common CWEs.
- The benchmark harness is how you prove the win. Optimize: `--discover deep`, all
  scanner backends installed, stacked Semgrep rulesets (`PW_SEMGREP_CONFIG`), `--test`
  set so fixes count as proven. Then publish `scorecard.md`.

## Next-step backlog (pick from here)
- [ ] Run `pytest` + a live multi-scanner scan once a shell with disk space is
      available (this build session's sandbox was out of disk, so the new code was
      verified by static review, not executed).
- [ ] Real Java/Spring sample repo to exercise the AI-fix path end-to-end.
- [ ] HTML dashboard rendering `patchwright-report.json` for the live demo.
- [ ] Reachability upgrade #2: real import/call-graph parse for Java instead of grep.
- [ ] Code-finding cross-confirmation: line-overlap fingerprint so semgrep+bandit
      on the same line merge (currently they stay separate; deps already merge on CVE).
```
```
