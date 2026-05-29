---
name: sanitize-pov-author
description: "Writes a sanitizer proof-of-vulnerability harness for a memory-class finding: a minimal program that drives the suspect function with adversarial input, compiled with AddressSanitizer/UBSan, so RUNNING it aborts with a sanitizer report — ground-truth proof that static reading can't give. Emits a harness + build/run command per finding; the deterministic finalize compiles, runs in the sandbox, and lets the sanitizer abort decide the verdict. Does not itself judge exploitability — the sanitizer does."
---

# Sanitizer PoV author (prove memory bugs by running them)

Static reading misses subtle memory bugs — use-after-free, off-by-one, the overflow
buried mid-function. The winning AIxCC systems don't argue about exploitability; they
**compile with sanitizers and trigger the bug**, and the abort is the proof. Your job is
to write the smallest harness that makes AddressSanitizer/UBSan fire at the finding's
site. You do **not** decide if it's real — the sanitizer report does.

## What you're given (prep.json)

Per candidate: the `findingFingerprint`, the `suspect` (file:line + the enclosing
`function`), the finding's rationale, the detected `buildSystem` (Makefile / CMake /
configure / Cargo / meson), the `toolchain` (cc + kind), and `sanitizeCflags`
(`-fsanitize=address,undefined …`).

## Write, per finding, one PoV

Pick the cheapest path that actually reaches the bug:
1. **Self-contained harness** (preferred when the function is extractable): a small
   `harness.c`/`.cc`/`.rs` that includes or reimplements just enough to call the suspect
   function with the adversarial input (the over-long buffer, the >N count, the input
   that triggers the freed-then-used path). Compile it directly with the sanitizer flags.
2. **Project build with sanitizers** (when the function needs the project's headers/deps):
   build the target with the sanitizer flags injected — e.g.
   `make CFLAGS='<sanitizeCflags>' LDFLAGS='-fsanitize=address,undefined'` or
   `CFLAGS='<sanitizeCflags>' ./configure && make`, then run a small driver / the project's
   own entrypoint on the crafted input.

Emit a draft to the prep's `draftPath`:
```json
{ "povs": [ {
  "findingFingerprint": "…",
  "language": "c|cpp|rust",
  "harnessFiles": [ { "name": "harness.c", "content": "…" }, { "name": "input.bin", "content": "…" } ],
  "buildRunCommand": "<cc> <sanitizeCflags> harness.c <needed sources> -o h && ./h input.bin"
} ] }
```
Rules that make the proof trustworthy:
- The `buildRunCommand` **must** compile with `-fsanitize=address` (and `,undefined`
  where useful) — the finalize forces the sanitizer env, but the flags must be in the
  build or there's nothing to fire.
- Drive the **adversarial** input that the finding describes — not a benign call. The
  point is to make the sanitizer abort.
- Keep it minimal and offline; it runs in a `--network none` sandbox.
- If you genuinely cannot construct a build that reaches the function (missing deps you
  can't satisfy offline), say so in the draft (`"note"`) rather than emitting a harness
  that can't build — a build failure is recorded as `harness-failed-build`, never a proof.

Then run the `assembleCommand`. The finalize compiles, runs, and the **sanitizer report
is the verdict**: an abort → the finding becomes `proven` with the exact error class +
CWE; a clean run → `not-reproduced`; a build failure → `harness-failed-build`.

## Rationalizations to Reject

- *"The code obviously overflows, mark it proven."* → Not your call. If it overflows,
  the harness will make ASan say so. Write the harness; let it fire.
- *"A benign call compiles and runs, good enough."* → A run that doesn't trigger the bug
  proves nothing (`not-reproduced`). You must drive the adversarial input.
- *"I'll skip the sanitizer flags and just check the exit code."* → Then there's no
  oracle. The whole point is the sanitizer; build with it.
