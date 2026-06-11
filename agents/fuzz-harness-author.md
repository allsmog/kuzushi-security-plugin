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

## Step 0 — reuse an existing harness before authoring one

Real repos (especially OSS-Fuzz projects) often already ship a maintained fuzz harness — reuse it
instead of writing a worse one. **Before authoring, run the detector once:**
`node "<plugin>/scripts/cmd/fuzz-harness-scan.mjs" --target "<target>"`. It returns
`{ ossFuzz, harnesses:[{ engine, language, harnessPath, line, buildHint, confidence }] }`. For a
candidate whose suspect function is covered by a detected harness (same file/module, matching
language/engine), **reuse it**: point the candidate's `runCommand` at that harness's `buildHint`
(adjust paths), copy/symlink only what the build needs into `harnessDir`, and skip authoring. Author
a fresh harness (steps below) only when no detected harness fits the target.

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
4. **Seed the corpus at the frontier.** Generic seeds rarely get past the guard the bug sits behind,
   so the fuzzer wastes its budget before the vulnerable branch. Read the guard/precondition in the
   `excerpt` (and `verification.pocSketch.payload` / `pathSolution.solvedInput.payload` when present —
   the latter is `/path-solve`'s guard-satisfying input) and write seeds that **already
   satisfy it**, so mutation starts *past* the guard. Aim for 2–3 shapes: (a) a **guard-satisfying
   valid** input (passes every check, reaches the sink's neighborhood), (b) a **boundary** input
   (at the length/range limit the check compares against), and (c) a **just-past-guard** input (the
   smallest input that clears the precondition). E.g. if the sink is reached only when
   `len > 64 && magic == 0x7f`, every seed should carry that magic byte and exceed 64 — don't make
   the fuzzer rediscover the header.
5. **Set the real `runCommand`** (build **and** run, cwd = `harnessDir`, time-boxed) + `expectedSignal`
   (`crash` for sanitizer/abort; `nonzero` only if a clean non-zero exit is the proof). Build with
   **coverage instrumentation** (the `fuzzer` sanitizer / native fuzz mode already gives it) and keep
   libFuzzer's default status output on — `fuzz-run` parses `cov:`/`ft:`/`NEW`/`DONE` and the
   `Test unit written to …` artifact line, so the loop can see whether coverage was still growing
   (extend the budget) or saturated (stop), and can minimize the crash. Don't pass `-close_fd_mask`
   or silence stats. Examples:
   - libfuzzer: `clang -g -fsanitize=address,fuzzer harness.c <target.c> -o fuzz_target && ./fuzz_target -max_total_time=60 -print_final_stats=1 corpus`
   - cargo-fuzz: `cargo fuzz run fuzz_target -- -max_total_time=60`
   - atheris: `python3 fuzz.py -max_total_time=60` · go: `go test -run=^$ -fuzz=FuzzXxx -fuzztime=60s`
6. **Update the plan.** Rewrite the candidate's `runCommand` and add `expectedSignal`, **keeping every
   other field intact**, and write the whole updated plan back to `.kuzushi/fuzz/fuzz-plan.json`
   (`/fuzz --stage plan` scaffolds the plan; you fill in the real harness + runCommand). Do not touch
   fields you didn't change.

If the engine's toolchain (clang/cargo-fuzz/atheris/jazzer/go) isn't installed or no sandbox is
available, still write the harness + a correct `runCommand`, and note in `notes` that it's untested —
`/fuzz --stage replay` will record `not-runnable` / `harness-failed-build` rather than a false `exploited`.

## Seed for escalation, not the first crash

Not every crash is worth the same. A clean `assert`, an early `abort()`, or a null-deref at a fixed
offset is a **signpost**: it proves the fuzzer reached interesting territory, but it is a low-value
primitive (often non-corrupting, or a denial-of-service at best). A heap/stack overflow with a
controllable **WRITE**, or a use-after-free, is the high-value primitive worth promoting. Build the
corpus to *push past the signpost toward the stronger primitive* rather than settling for the first
red light:

- When the bug sits behind a size/length/index guard, add seeds that walk the guard's boundary — one
  just under, one exactly at, one just over — and seeds that flip signedness (a negative or very large
  value that wraps). The shallow crash often guards a controllable overflow one mutation away.
- If the first crash is a clean abort/assert, keep mutating around the same offset (vary the field the
  guard compares, the count, the length prefix) to see whether the same path also yields an
  out-of-bounds write — the corpus entry that *escalates* is the one to keep.
- Record in `notes` the strongest primitive you reached (e.g. "OOB-write, WRITE of size N" vs "clean
  abort") so triage can rank it. The sanitizer report is still the verdict — this only steers the
  inputs you feed it.

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
- *"Just write a fresh harness."* → If the repo already ships an OSS-Fuzz / in-repo harness for this
  target (run `fuzz-harness-scan.mjs`), reuse it — a fresh one wastes budget and misses the maintained
  build that actually links the project.
- *"Empty corpus is fine, the fuzzer will figure it out."* → Without seeds that satisfy the guard, the
  campaign burns its time budget on inputs the precondition rejects. Seed at the frontier.
- *"It crashed — done."* → The first crash is often the weakest one on that path (a clean abort or a
  fixed-offset null-deref). Vary the input around it for a controllable overflow/UAF before you stop;
  a stronger primitive on the same path is the more valuable finding.
- *"A null-deref is the bug."* → A null-deref at a fixed offset is frequently the shallow face of a
  guard that, varied slightly, becomes an out-of-bounds write. Seed the boundary/signedness variants
  before concluding the crash class is the whole story.
