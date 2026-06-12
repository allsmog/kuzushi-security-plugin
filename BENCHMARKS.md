# Benchmarks

Kuzushi's benchmark contract is defender value: verified, reproducible,
patch-validated security outcomes with low review burden. Raw candidates are not
counted as wins until evidence advances through the proof ladder.

## Smoke Benchmark

Run:

```bash
npm run bench:smoke
```

The smoke benchmark uses a temporary repository and no network. It validates:

- `finding.v1` normalization and proof-state transitions.
- `verification.v1` and `fix.v1` attachment contracts.
- `ci-locked` policy profile behavior.
- SARIF output carrying proof state, policy digest, and provenance metadata.

## Recall / Precision Corpus

Run:

```bash
node scripts/cmd/benchmark.mjs        # whole bundled corpus
node scripts/cmd/benchmark.mjs --case node-command-injection
```

`/benchmark` scores a run's `findings.json` against a **ground-truth manifest** — each case
under `bench/cases/` plants a real bug *and* a safe decoy that looks like one but must not be
flagged. The scorer reports:

- **recall** — planted bugs found / planted bugs present (are we missing bugs?).
- **precision** — true hits / all active hits (do we flag decoys?).
- **falseProofRate** — `proven` hits on decoys / all `proven` (did we *prove* a non-bug?).

Grow it whenever a new bug class is confirmed — author a `vuln` expectation for the bug and a
`safe` expectation for its guarded sibling so the case exerts both recall and precision pressure.
Score a live external target with `--target <repo> --ground-truth <manifest.json>`.

### Two gates, and why both exist (measurement integrity)

There are two CI tests over the corpus, and they measure different things — conflating them is
how a broken producer hides behind a green build:

- **`test/benchmark-corpus.test.mjs`** scores the **frozen, hand-recorded `findings.json`** in
  each `--case` directory. Its recall = precision = 1.0 is a property of the **scorer wiring and
  the recorded snapshot** — it is *tautological* w.r.t. the producers (the findings were authored
  to match `expected.json`). It catches a regression in the scorer, not a producer that stopped
  firing.
- **`test/bench-live-recall.test.mjs`** is the real producer-firing net: it runs the
  deterministic **prepare** phase live (no LLM) on every case and asserts the planted site is
  actually routed. If a change breaks routing, this fails. It pins a **site-level** (±6-line)
  recall floor in addition to file-level, because "ranked the file" is not "found the site".

`npm run bench` writes `scoreboard.md` with both a `deep (file)` and a `deep (site)` column; the
gap between them is the share of "recall" that is only file-ranking. Keeping it visible is
deliberate — a 100% file number with an 88% site number is the honest read, not a rounding error.

## Release Metrics

Each release should report:

- Candidate, confirmed, proven, patched, and remediated counts.
- False positives per KLOC on fixtures.
- Median verification time for supported CWEs.
- Patch PoC+ pass rate.
- Rule-pack accepted/rejected counts and digest reproducibility.
- Fuzz crash groups, minimized repro rate, and promote-to-proven rate.

## Target Corpora

The intended larger benchmark set is:

- CWE-Bench-Java for LLM-assisted static-analysis recall.
- Vul4J / VJBench for repair and patch-validation quality.
- PrimeVul for broader vulnerability detection and repair.
- OSS-Fuzz projects for parser/native discovery.
- AIxCC public tasks for CRS-style discovery and patching.
- Kuzushi fixtures for command and artifact regression tests.
- Historical real PRs with known security fixes for maintainer relevance.
