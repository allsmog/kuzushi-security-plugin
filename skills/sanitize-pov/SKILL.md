---
name: sanitize-pov
description: Prove a memory-class finding by RUNNING it under AddressSanitizer/UBSan — the empirical "find-by-execution" path that catches subtle bugs (use-after-free, buried overflow) static reading misses. Compiles a harness with sanitizers in a --network none sandbox; a sanitizer abort is ground-truth proof and names the exact error class + CWE. Executes code — consented user action. Attaches a poc block; promotes the finding to proven.
context: fork
agent: sanitize-pov-author
user-invocable: false
---

# Sanitize PoV (prove memory bugs under a sanitizer)

The CONFIRM-phase empirical proof for **memory-class** findings (native/systems, or any
CWE-119/120/121/122/125/416/787/… ). It is kuzushi's version of the AIxCC core: don't
reason about whether the bug is real — compile with AddressSanitizer/UBSan and trigger
it; the abort is the proof, and it tells you the exact error class.

**This executes code.** It builds and runs a harness, so it is a **consented** action,
like `/poc` and `/fuzz` — propose it and run only on the user's say-so, and only in a
sandbox (`--network none`; local execution requires explicit `trustLocal`).

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/sanitize-pov-prepare.mjs" --target "<repo>"`
   (optionally `--input '{"findingFingerprint":"<fp>"}'` to target one). It gathers the
   memory findings, the suspect functions, the build system, and the toolchain. If it
   reports `no-toolchain`, tell the user a C/C++ compiler (clang/gcc) is needed and stop.
2. Read the prep. For each candidate, the **sanitize-pov-author** agent writes a minimal
   harness that drives the bug with adversarial input, compiled with `sanitizeCflags`,
   and a `buildRunCommand`. Write the `{ povs:[…] }` draft to `draftPath`.
3. **Get the user's OK to execute**, then run the `assembleCommand`. The finalize
   compiles + runs each harness in the sandbox and lets the **sanitizer report decide**:
   an ASan/UBSan abort → the finding is `proven` with the reported error class + CWE; a
   clean run → `not-reproduced`; a build failure → `harness-failed-build` (never a false
   proof).
4. Report the proven findings (fingerprint, error class, CWE, the crashing frame) and the
   ones that didn't reproduce.

## When NOT to use

- For non-memory findings (authz/logic/injection in managed languages) — there's no
  sanitizer to fire; use `/verify` + `/poc`.
- When no compiler/build is available offline, or the function can't be reached without
  unsatisfiable deps — record `harness-failed-build`, don't fake a proof.
- To *find* new bugs from scratch — it proves a finding a hunt already surfaced. (Pair
  with `/fuzz` to *discover* via the same sanitizer oracle over many inputs.)

## Rationalizations to Reject

- *"ASan didn't fire, but the code is clearly buggy — call it proven."* → No. A
  non-firing run is `not-reproduced`; either the harness didn't reach the bug or the
  premise was wrong. The sanitizer is the oracle, not your reading.
- *"Build failed, but it would've crashed."* → `harness-failed-build` is not a proof.
  Fix the build or say it couldn't be built offline.
- *"Skip the sandbox, just run it here."* → Local execution is gated on explicit consent
  (`trustLocal`); default is the `--network none` sandbox. Never run untrusted target
  code on the host without it.
