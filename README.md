# 🛡️ Patchwright

**Closed-loop, validated, AI vulnerability remediation for Bitbucket.**

Every scanner on the market is good at *finding* vulnerabilities and bad at *fixing*
them. Snyk only bumps dependency versions. Semgrep's autofix is brittle rule
templates. AI tools dump unverified suggestions on a human. **Patchwright is the
only loop that proves the fix worked before shipping it.**

## The differentiator: the validation loop

```
  scan (N scanners in parallel)
        │
        ▼
  merge + cross-confirm    ← same vuln from 2 scanners = 1 finding, higher trust
        │
        ▼
  contextual risk score    ← reachability + confirmation + fixability, not raw CVSS
        │
        ▼
  ┌─────────────────────────────────────────────┐
  │  AI generates a MINIMAL patch                │
  │       │                                      │
  │       ▼                                      │
  │  apply in sandbox → re-scan THIS finding     │
  │       │            → run the test suite      │
  │       ▼                                      │
  │  gone & green?  ──no──► feed failure back,   │
  │       │                 retry (max 3)        │
  │      yes                                     │
  └───────┼─────────────────────────────────────┘
          ▼
  accept patch (confidence-scored) → open ONE PR
```

The model never approves its own work. A scanner and your tests are the judge.
That's what lets Patchwright **auto-merge** instead of nagging.

## How it's positioned vs Snyk (honest)

Snyk's Agent Fix (2026) also validates fixes in a sandbox loop, so "validated
remediation" alone isn't a differentiator anymore. Patchwright's real edge is
being an **open, zero-cost ensemble**: many independent engines unioned together
(higher recall than a single engine), every fix backed by **executable proof**
(re-scan / tests / PoC), and nothing leaving your infrastructure.

| Axis                                   | Snyk            | Patchwright        |
|----------------------------------------|-----------------|--------------------|
| Detection engine                       | 1 (tuned, proprietary) | ensemble of 7 + AI |
| Multi-engine union recall              | ✗               | ✓                  |
| Cross-engine confirmation              | ✗               | ✓                  |
| Validated/agentic fix loop             | ✓ (Agent Fix)   | ✓                  |
| PoC-test proof for AI findings         | ✗               | ✓                  |
| Open / self-hosted / no per-seat cost  | ✗               | ✓                  |
| Per-vuln accuracy on common CWEs       | **strong**      | depends on backends |

Don't take the rows on faith — **measure it**. See `patchwright/benchmark/`:
it scores Patchwright and Snyk on the *same* ground truth and emits a scorecard
(recall / precision / F1 / proven-fix-rate).

## Scanner backends (any subset; the tool adapts to what's installed)

| Scanner       | Covers                                   | Cross-confirms with |
|---------------|------------------------------------------|---------------------|
| `trivy`            | deps + IaC misconfig + secrets           | osv, depcheck, checkov, gitleaks |
| `osv-scanner`      | transitive deps (Maven/Gradle/npm/pip/…) | trivy, depcheck     |
| `dependency-check` | OWASP SCA, strong on Java/Maven          | trivy, osv          |
| `semgrep`          | SAST (multi-language, incl. Java)        | bandit              |
| `bandit`           | Python-tuned SAST                        | semgrep             |
| `checkov`          | deep IaC / cloud posture                 | trivy               |
| `gitleaks`         | secrets across full git history          | trivy               |

More backends ⇒ more vulns found **and** more cross-confirmation. Dependency
findings from Trivy + OSV that share a CVE collapse into one higher-trust finding.

## AI discovery (Mythos-inspired, fully defensive)

Pattern scanners only find what a rule already describes. The `ai-discovery`
layer hands source code to the model and asks it to **reason** about flaws the
rules miss — broken authz, insecure deserialization, SSRF, path traversal,
injection through non-obvious data flow, TOCTOU, logic bugs.

In `deep` mode it does **cross-file taint analysis**: `context.py` assembles the
target file plus neighbor files that reference its symbols, tags untrusted
sources (`@RequestParam`, `getParameter`, …) and dangerous sinks (`createQuery`,
`Runtime.exec`, `readObject`, …), and asks the model to trace input from a source
in a controller to a sink in a service/repository — the inter-file data flow that
single-file scanners structurally cannot see, where the deep Spring vulns live.

It never writes exploits. For each suspected flaw it writes a **proof-of-concept
security test that asserts the secure behavior** — a test that *fails on the
vulnerable code*. That gives two credibility tiers:

- **Confirmed** — the PoC reproduced the vuln in a sandbox. Executable evidence;
  eligible for auto-fix, and the fix is accepted only once the PoC flips to
  passing **and** your suite stays green. No model self-grading.
- **AI-suspected** — no reproducing PoC. Surfaced for human review, never
  auto-merged.

```bash
patchwright scan ./repo --discover deep      # full-source sweep (widest net)
patchwright fix  ./repo --discover augment   # only re-examine flagged files (default)
patchwright scan ./repo --discover off       # OSS scanners only
```

Honest scope: this is **not** Claude Mythos (a non-public frontier model behind
Anthropic's Project Glasswing). It won't autonomously chain zero-days. It does
push detection beyond rule engines and proves the real findings — which is the
realistic, defensible edge over tools that just wrap Semgrep/Trivy.

## Install & run

```bash
pip install -e .

export ANTHROPIC_API_KEY=sk-...        # enables AI code fixes (dep fixes work without it)

patchwright scan  ./myrepo                       # detect only
patchwright fix   ./myrepo --test "pytest -q"    # detect + validated fix (dry run)
patchwright apply ./myrepo --test "pytest -q"    # write validated patches to disk
patchwright pr    ./myrepo --base main           # bundle validated fixes into ONE Bitbucket PR
```

### Java / Spring

Dependency fixes for Maven `pom.xml` are deterministic and XML-aware: both literal
`<version>` and `${property}` references are handled, and reachability is computed
from the Maven `groupId` import namespace (not the artifact name). Gradle string
notation works via the generic pin path. Java SAST findings flow through the AI-fix
loop like any other code finding.

### Bitbucket auto-PR

`patchwright pr` writes every *validated* patch, commits to a branch, pushes, and
opens a single PR whose body is an **evidence table** (vuln → fix → re-scan + test
proof). Set:

```bash
export BITBUCKET_WORKSPACE=... BITBUCKET_REPO=... BITBUCKET_TOKEN=... BITBUCKET_USER=...
```

Add `--dry-run` to commit locally and print the PR body — the demo works fully
offline. `bitbucket-pipelines.yml` wires the whole flow into CI.

Exit code is non-zero if any unfixed finding ≥ `--fail-on` (default HIGH) remains,
so it doubles as a CI gate.

## Farm integration (system-of-record loop)

Your existing loop is: internal tool reads a finding from the **Farm API** →
Snyk detects/fixes → results sync back to Farm. Patchwright runs the same loop
and beats it on every leg:

1. **Resolve + enrich** — for each finding *instance* (keyed by Patchwright's
   stable fingerprint) Patchwright asks Farm for its `farm_id` and state. It
   respects `suppressed` / `accepted_risk` items (never re-litigates triage).
2. **Fix (the edge)** — the 7-scanner ensemble + cross-file AI discovery finds
   vulns Snyk alone misses, and every fix is **validated** (re-scan + tests, or a
   PoC test for AI findings). You sync *proven* fixes, not suggestions.
3. **Sync back** — idempotent, evidence-rich updates keyed by `farm_id`:
   `FIXED_VALIDATED` (with the proof + PR link), `NEEDS_REVIEW`, `NEW` (a vuln
   Farm didn't have), or `OPEN`. Re-running never duplicates.

```bash
export FARM_API_URL=https://farm.internal/api
export FARM_API_TOKEN=...            # bearer, or FARM_API_HEADER for a custom header
patchwright pr ./repo --base main    # resolve -> validated fix -> open PR -> sync
patchwright scan ./repo              # resolve/enrich only (no sync)
patchwright fix ./repo --no-sync     # opt out of syncing
export FARM_SYNC_DRY_RUN=1           # print the sync payload instead of POSTing
```

It degrades gracefully: no `FARM_API_URL` (or any API error) and Patchwright runs
exactly as before with empty farm fields. The request/response contract and all
env vars are documented at the top of `patchwright/farm.py` — point it at your
endpoint or a thin shim.

**Why it outbeats the incumbent:** Snyk syncs *suggested* fixes; Patchwright syncs
fixes proven by re-scan + tests + PoC. The ensemble reports vulns Snyk misses as
`NEW`. And reconciliation closes what's resolved / reopens regressions on every
run — so Farm stays accurate without manual cleanup.

## Benchmark vs Snyk

Prove it, don't claim it. The harness in `patchwright/benchmark/` runs Patchwright
and Snyk against the same ground truth and prints a scorecard:

```bash
python -m patchwright.benchmark run --repo ./target --truth gt.json \
    --test "mvn -q test" --discover deep --compare snyk:snyk-code.sarif --out scorecard
```

Full workflow (standard OWASP Benchmark corpus + your own repo) in
`patchwright/benchmark/README.md`.

## Tests

```bash
pip install -e ".[dev]"
pytest            # covers dedup/cross-confirm, reachability, the accept/reject
                  # validation loop, sandbox isolation, Maven pinning, AI-discovery
                  # tiering, and the benchmark scoring math
```

## Extending

Add a scanner: subclass `Scanner` in `patchwright/scanners/`, map its output to
`Finding`, register in `scanners/__init__.py`. The validator automatically re-scans
each finding with the exact scanner that produced it. Nothing else changes.
