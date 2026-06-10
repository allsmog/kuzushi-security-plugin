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

The corpus is the regression net for the producers; `test/benchmark-corpus.test.mjs` asserts it
stays at recall = precision = 1.0 with zero false proofs. Grow it whenever a new bug class is
confirmed — author a `vuln` expectation for the bug and a `safe` expectation for its guarded
sibling so the case exerts both recall and precision pressure. Score a live external target with
`--target <repo> --ground-truth <manifest.json>`.

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
