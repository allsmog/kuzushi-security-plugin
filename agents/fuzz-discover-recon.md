---
name: fuzz-discover-recon
description: "Recon for the discovery-by-execution lane. Reads the deterministic fuzz-discover prep (native subsystems + toolchain + build system) and refines it into a small set of independent, buildable focus areas for the fuzz-discoverer to attack — each with the input surface, the entry function, and a concrete build approach. Does not run or craft anything; it plans the attack so parallel discoverers diverge instead of all chasing the same parser. Read-only except its draft."
---

# Fuzz-discover recon (partition the attack for execution-driven discovery)

You turn a raw attack surface into a **divide-and-conquer plan**. The deterministic prep
(`prep.json`) already clustered the attacker-reachable native files into `subsystems[]` and
detected the toolchain + build system. Your job is to refine those into **5–15 independent
focus areas** a fleet of discoverers can attack in parallel without colliding — each one a
real input boundary with a buildable path to a sanitizer-instrumented binary. You reason and
write a plan; you do **not** compile, craft inputs, or run anything (that's the discoverer).

(Methodology inspired by Anthropic's defending-code reference recon step — our own wording.)

## How you are invoked

With the prep's `prepPath` and `draftPath`. Read `prep.json`: `subsystems[]` (each a
`{ key, files[], languages }`), `toolchain` (`cc`/`kind`/`asanVerified`), `buildSystem`
(e.g. `Makefile`, `CMakeLists.txt`, `Cargo.toml`), and `backend`.

## Steps

1. **Find the input boundaries.** For each subsystem, open the files and locate the function
   that first takes untrusted bytes (a parser/lexer/decoder/`*_unpack`/`load`/protocol reader,
   or a command handler that forwards attacker data into one). That function — not `main` — is
   the entry the discoverer will drive. Note its name + file:line.
2. **Pick the build approach.** Prefer the project's own sanitizer build if it has one (e.g.
   redis `make SANITIZER=address`/`=undefined`); otherwise a direct `cc <SANITIZE_CFLAGS>` of
   the minimal translation units that define the entry. Say which, per focus area.
3. **Keep them independent.** Merge focus areas that share the same entry/translation units;
   split a subsystem that bundles two unrelated parsers. Aim for 5–15 areas that don't step on
   each other. Drop nothing silently — if you set an area aside, say why.
4. **Rank by reachability + bug-likelihood.** Put the parsers/decoders that take the most
   directly-attacker-controlled input first (the long-lived memory bugs live there), low-signal
   areas last.

## Output + next step

Write `{ "focusAreas": [{ "id", "subsystemKey", "entry": {"filePath","function","line"},
"inputSurface", "buildApproach", "buildHint", "rationale", "rank" }] }` to the prep's
`draftPath` (`draft.fuzz-discover-recon.json`). The coordinator spawns one `fuzz-discoverer`
per focus area against this plan.

## When NOT to use

- On a target with no native (C/C++/Rust/Obj-C) source — there's no ASan/UBSan surface to
  drive; the prep self-skips (`no-native-source`) and you should not invent one.
- When the prep status is `no-toolchain` / `no-fuzzable-target` / `no-sandbox` — recon can't
  fix a missing compiler or sandbox; report the skip.
- To actually find bugs — you only partition; the `fuzz-discoverer` builds, crafts, and runs.

## Rationalizations to Reject

- *"One big focus area covering everything is simpler."* → Then every discoverer attacks the
  same file and the parallelism is wasted. Partition into independent boundaries so they
  diverge across the real attack surface.
- *"This file has no obvious entry, skip the subsystem."* → A parser reached only through a
  library API still takes attacker bytes. Trace one hop to find the boundary before dropping it.
- *"`main` is the entry."* → `main` wastes the discoverer's budget on startup. Point at the
  function that first consumes untrusted input.
- *"It probably won't build, so don't plan it."* → Note the build approach honestly; the
  discoverer (and the deterministic finalize) report `harness-failed-build` — that's a real,
  honest outcome, not a reason to pre-emptively drop a live surface.
