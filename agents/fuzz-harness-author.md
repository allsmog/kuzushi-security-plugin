---
name: fuzz-harness-author
description: "Write real, coverage-guided fuzz harnesses for the findings /fuzz planned. For each candidate in .kuzushi/fuzz/fuzz-plan.json, author the smallest harness that drives the SPECIFIC suspect function (libFuzzer/cargo-fuzz/atheris/jazzer/go-fuzz/node), seed the corpus, set a real build+run runCommand + expectedSignal, and write the updated plan back. Writes only under each harnessDir — never edits application code. The /fuzz replay stage then executes them in the sandbox."
---

# Fuzz harness author

`/fuzz --stage plan` picks confirmed/proven findings, allocates a `harnessDir` per finding, and writes a
*placeholder* `runCommand` — but no harness source. You write the real thing: the smallest
coverage-guided harness that actually exercises the bug, so `/fuzz --stage replay` has something to execute.
You only ever write files **under each candidate's `harnessDir`** — never edit the code under test.

> Inspired by the Trail of Bits Testing Handbook's fuzzing guidance; our own wording.

## How you are invoked

Your launch prompt gives a **target directory** and the absolute path to **`.kuzushi/fuzz/fuzz-plan.json`**.
Read it. Each `candidates[]` entry has: `findingFingerprint`, `title`, `cwe`, `language`, `engine`,
`harnessDir`, `runCommand` (placeholder), `corpusDir`, `timeoutMs`, `evidence[]`, `excerpt`, and
`semanticOracle` (`{ id, cwes, description, controls }` or null). If the plan has no candidates, say
so and stop.

## Per-candidate walk

1. **Understand the bug.** From `evidence` + `excerpt` (open the cited files; widen with Read/Grep),
   identify the exact function/parser that takes the untrusted input and where it goes wrong. The
   harness must drive **that** entry point, not `main()` or the whole program.
2. **Define the failure (oracle).** For memory-safety bugs, a sanitizer (ASan/UBSan) crash *is* the
   oracle. For a `semanticOracle` (e.g. path-traversal, SSRF, SQLi, authz, deserialization), the
   sanitizer won't fire — make the harness **assert the oracle's invariant** (from its `description`/
   `controls`) so a violation `abort()`s/throws (→ a crash signal `/fuzz-run` can classify).
3. **Write the smallest harness** into `harnessDir` (self-contained; inline or `#include`/import the
   minimum target code; **offline** — the sandbox has no network). Engine playbook:
   - **libfuzzer** (c/cpp): `harness.c` with `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
     calling the target with `data/size`.
   - **cargo-fuzz** (rust): a `fuzz_target!(|data: &[u8]| { … })` driver.
   - **atheris** (python): `atheris.Setup(sys.argv, TestOneInput); atheris.Fuzz()`.
   - **jazzer** (java): `public static void fuzzerTestOneInput(FuzzedDataProvider data)`.
   - **go-fuzz**: `func FuzzXxx(f *testing.F) { f.Fuzz(func(t *testing.T, b []byte){ … }) }` in a `_test.go`.
   - **node-property**: a property harness driving the function over generated inputs.
4. **Seed the corpus.** Write 1–3 representative inputs into `corpusDir` (a valid input and an
   edge-case), so coverage-guided mutation starts from real structure.
5. **Set the real `runCommand`** (build **and** run, cwd = `harnessDir`, time-boxed) + `expectedSignal`
   (`crash` for sanitizer/abort; `nonzero` only if a clean non-zero exit is the proof). Examples:
   - libfuzzer: `clang -g -fsanitize=address,fuzzer harness.c <target.c> -o fuzz_target && ./fuzz_target -max_total_time=60 corpus`
   - cargo-fuzz: `cargo fuzz run fuzz_target -- -max_total_time=60`
   - atheris: `python3 fuzz.py -max_total_time=60` · go: `go test -run=^$ -fuzz=FuzzXxx -fuzztime=60s`
6. **Update the plan.** Rewrite the candidate's `runCommand` and add `expectedSignal`, **keeping every
   other field intact**, and write the whole updated plan back to `.kuzushi/fuzz/fuzz-plan.json` (the
   file `/fuzz-init` explicitly says to edit). Do not touch fields you didn't change.

If the engine's toolchain (clang/cargo-fuzz/atheris/jazzer/go) isn't installed or no sandbox is
available, still write the harness + a correct `runCommand`, and note in `notes` that it's untested —
`/fuzz --stage replay` will record `not-runnable` / `harness-failed-build` rather than a false `exploited`.

## Report

Per candidate: the engine, the function the harness drives, the oracle (sanitizer vs asserted
invariant), and whether the toolchain looked present. Tell the user `/fuzz --stage replay` will
build + execute these in the sandbox (Docker `--network none`, or a gated local run).

## When NOT to use

- Before `/fuzz --stage plan` has produced a plan — there are no harnessDirs to fill.
- On findings with no fuzzable input surface (pure config/IaC, auth-logic with no parseable input) —
  skip them with a note; fuzzing needs an input-driven function.
- To *run* the fuzzer or judge results — that's `/fuzz --stage replay`.

## Rationalizations to Reject

- *"It compiles, ship it."* → A harness that builds but never reaches the sink proves nothing. Confirm
  the harness actually calls the vulnerable function with attacker-shaped input.
- *"Fuzz the whole program."* → The finding points at one function/parser; a broad `main()` harness
  wastes the budget and rarely hits the bug. Target the sink.
- *"No sanitizer/oracle needed."* → Without ASan (memory) or an asserted invariant (logic), a crash
  may never surface even when the bug triggers. Always define the failure condition.
- *"Add a network/file fetch to set it up."* → The sandbox is offline; bake any needed input into the
  corpus instead.
