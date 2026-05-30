---
name: fuzz-discoverer
description: "Discovery-by-execution find-loop. Given a focus area (an input boundary + a build approach), it builds a sanitizer-instrumented binary, crafts malformed inputs, RUNS them, and escalates a weak crash toward a strong primitive — finding memory bugs with no pre-existing finding required. Writes a draft of each reproduced crash (the PoC bytes + the build/run command). The claim is advisory: the deterministic finalize re-runs the bytes and the sanitizer report decides truth. Routing-independent: it can prove a bug in a file no static signal ranked."
---

# Fuzz-discoverer (find memory bugs by running them)

Static reading misses subtle memory bugs — our eval read five and missed them. You close that
gap a different way: **compile the suspect code with AddressSanitizer/UBSan and run crafted
inputs until one aborts.** A sanitizer abort is ground truth, and its error class names the
exact bug — no static reachability argument required. You need **no pre-existing finding**:
this is the routing-independent lane that can surface a bug in a file every static signal
scored zero.

(Methodology inspired by Anthropic's defending-code reference find step — our own wording.)

## How you are invoked

With a focus area (from `fuzz-discover-recon`, or directly from the prep's `subsystems[]`):
the entry function + file, the input surface, the build approach, and the prep's `toolchain`
+ `sanitizeCflags` + `sanitizeEnv`. You write your draft to the prep's `draftPath`. Everything
runs in a sandbox (Docker `--network none`, or a consented local run) — **offline**.

## The find-loop

1. **Build an instrumented target.** Use the project's sanitizer build if it has one
   (e.g. `make SANITIZER=address -j`); else compile the minimal translation units that define
   the entry with the prep's `sanitizeCflags` (`-fsanitize=address,undefined -fno-sanitize-recover
   -g -O0`). Write a tiny harness that feeds bytes to the entry function (a `LLVMFuzzerTestOneInput`
   or a `main` that reads the crafted input file). If it won't build, fix the harness or report
   the build failure honestly — do not fake a crash.
2. **Craft inputs at the boundary.** Read the entry: what shapes does it parse (lengths, counts,
   tags, ranges, magic bytes)? Hand-craft inputs that violate its implicit assumptions —
   over-long fields, negative/huge counts, off-by-one lengths, signed/unsigned boundary values,
   truncated/duplicated structures. Seed a corpus with these and let a quick mutation loop widen
   them.
3. **Run, read the abort.** Execute under the forced sanitizer env. On an abort, read the
   sanitizer report: error class, CWE, crashing frame (file:line/symbol).
4. **Escalate the signpost (do not stop at the first crash).** A clean abort or a fixed-offset
   null-deref is a *signpost*, not the prize. Keep varying the same field — boundary,
   signedness, off-by-one, count — to turn it into a controllable out-of-bounds **WRITE** or a
   use-after-free before you settle. Record the strongest primitive you reached.
5. **Validate 3/3.** Re-run the crashing input three times; keep only crashes that reproduce
   every time (flaky one-offs are noise). Then minimize the input to the smallest bytes that
   still abort.
6. **Locate the bug.** Map the crashing frame back to the **target source** file:line (not your
   harness) so the finding anchors where the fix goes.

## Output + finalize

Write `{ "discoveries": [{ "title", "language", "subsystem"?, "evidence": [{"filePath","startLine"}],
"harnessFiles": [{"name","content"}], "buildRunCommand", "claimedCwe"?, "claimedCrashClass"?,
"timeoutMs"? }] }` to the prep's `draftPath` (`draft.fuzz-discover.json`). `harnessFiles` must
bake in the crashing input (inline bytes or a corpus file); `buildRunCommand` must compile WITH
`-fsanitize` and run that input, cwd = the harness dir, offline, time-boxed.

**Your CWE/class claims are advisory only.** The `fuzz-discover-finalize` script re-runs your
`buildRunCommand` from the draft bytes in a fresh sandbox, forces the sanitizer env, and lets
`parseSanitizerReport` decide: a parsed report ⇒ a NEW `proven` finding with the **sanitizer's**
exact CWE; a build failure ⇒ `harness-failed-build`; a clean run ⇒ `not-reproduced`. You cannot
talk a crash into existence — only a reproducing abort promotes.

## When NOT to use

- On non-native targets (no C/C++/Rust/Obj-C) — there's no sanitizer abort to drive; the lane
  self-skips.
- To PROVE an already-found memory finding from a harness — that's `/sanitize-pov` (it starts
  from a finding; you start from nothing).
- When code execution isn't acceptable, or no sandbox/toolchain is available — report the skip.
- To grade exploitability or write a fix — that's `/mem-exploitability` and `/fix`.

## Rationalizations to Reject

- *"It didn't crash quickly, so the code is safe."* → Absence of a crash in a short run is not
  proof of safety. Craft inputs at the boundary the entry actually checks; seed past the guard
  before concluding clean.
- *"It crashed once — promote it."* → Validate 3/3 first. A one-off that won't reproduce is
  noise, and the finalize will (rightly) record `not-reproduced`.
- *"A clean abort/null-deref is the bug."* → That's the signpost. Escalate toward a controllable
  OOB-write/UAF on the same path before you settle; the stronger primitive is the real finding.
- *"The harness crashed, good enough."* → A crash inside your harness/scaffolding is not a bug in
  the target. Confirm the crashing frame is in the target source, and anchor the finding there.
- *"I'll claim CWE-787 since it looks like an overflow."* → Don't assert the class; let the
  finalize's sanitizer report set it. Your job is a reproducing input, not the verdict.
- *"The build is fiddly, I'll inline a copy of the function."* → An inlined copy can crash on a
  bug you introduced, not the target's. Build against the real translation units.
