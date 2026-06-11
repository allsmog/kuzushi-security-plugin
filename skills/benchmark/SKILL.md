---
name: benchmark
description: Measure recall / precision / false-proof rate of the pipeline against a ground-truth manifest. Scores either the bundled planted-vulnerability corpus (regression) or a live run's findings.json against a manifest you supply. Deterministic — no agent, no network. Use to prove a change to the producers helps rather than hurts.
context: inline
user-invocable: true
---

# Benchmark

You can't call bug-finding "world-class" — or catch a regression in it — without a
number. `/benchmark` scores findings against ground truth and reports the three metrics
that matter: **recall** (are we missing bugs?), **precision** (do we cry wolf?), and
**falseProofRate** (did we *prove* a non-bug? — the soundness failure differential
testing guards).

## Run it

- **Bundled corpus (regression):**
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/benchmark.mjs"`
  scores every case under `bench/cases/` using its recorded `findings.json`. Add
  `--case <name>` for one case.
- **A live run:**
  `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/benchmark.mjs" --target "<repo>" --ground-truth "<manifest.json>"`
  scores `<repo>/.kuzushi/findings.json` after you've run the pipeline.

Flags: `--strict` (an active finding matching no expectation counts as a false positive —
only fair when the manifest is exhaustive), `--line-tolerance N` (default 5),
`--no-match-cwe` (match on file+line only).

## Ground-truth manifest

`{ "expectations": [ { "id", "kind": "vuln" | "safe", "cwe", "filePath", "line" } ] }`.
A `vuln` is a real bug the tool **should** find; a `safe` is a decoy that looks like one
and **must not** be flagged. A decoy that gets an active finding is a false positive; a
decoy that gets a *proven* finding is a false proof. Author manifests from confirmed bugs
(and their guarded siblings) so the corpus encodes both recall and precision pressure.

## Reading the result

`corpus` aggregates across cases; `cases[].perExpectation` shows each hit/miss. A drop in
`recall` means a producer started missing a bug class; a drop in `precision` or any
`falseProofs` means it started over-promoting. Wire the corpus run into CI so either
regresses loudly.

## When NOT to use

- To **find** bugs — `/benchmark` measures a run that already happened; it runs no analysis.
- On a target with no ground-truth manifest — without annotated expectations there is
  nothing to score against; write the manifest first (or use the bundled corpus).
- As a security verdict — a green benchmark means the corpus didn't regress, not that a
  given repo is bug-free.

## Rationalizations to Reject

- *"Recall is 1.0 on the corpus, so the tool finds everything."* → The corpus is a tiny
  planted set; it proves *non-regression on known shapes*, not coverage of the unknown.
  Grow the corpus when you confirm a new bug class, or the number lies by omission.
- *"Precision dipped but the new hits look plausible."* → Plausible ≠ correct. A dip means
  a decoy got flagged; open it and confirm the guard before accepting the change.
- *"falseProofs went up but the bugs are real."* → A false proof is a *proven* hit on a
  decoy — the harness fired on a non-bug. That's a soundness break regardless of intent;
  fix the harness/differential gate before shipping.
