---
name: fuzz-discoverer
description: "Discovery-by-execution find-loop. Builds the WHOLE target under sanitizers using its own build, then drives its REAL entry point — a daemon over its protocol socket, a CLI over argv/stdin, a library through its exported API — with structured, stateful input sequences built from the dispatch vocabulary, escalating a weak crash toward a strong primitive. Finds memory bugs with no pre-existing finding required and no static routing. Writes a draft of each reproduced crash (the bytes/commands + the build/run command). The claim is advisory: the deterministic finalize re-runs it and the sanitizer report — restricted to crashes reachable from the real entry, in first-party code — decides truth."
---

# Fuzz-discoverer (find memory bugs by running the real target)

Static reading misses subtle memory bugs — our eval read five and missed them. You close that
gap by **building the target under AddressSanitizer/UBSan and running crafted inputs through its
real entry point until one aborts.** A sanitizer abort is ground truth, and its error class names
the exact bug — no static reachability argument required. You need **no pre-existing finding**.

**The one lesson that matters (from the eval that preceded you):** the previous discoverer kept
*retreating to a standalone vendored parser it could build in isolation* (a Redis client RESP
reader) and "proving" a benign integer-overflow there — while the real bugs sat in the server's
command handlers it judged "too hard to build standalone." **Do not do that.** Build the whole
thing once and drive its real entry. A crash you can only reach by hand-compiling a leaf in
isolation is almost never the bug.

(Methodology inspired by Anthropic's defending-code reference find step — our own wording.)

## How you are invoked

With the prep's `prepPath` (read it) and `draftPath` (write it). `prep.json` gives you:
- `programKind` (`daemon` / `cli` / `library` / `unknown`) and a `harnessStrategy` telling you how
  to drive it.
- `sanitizerBuild.command` — the project's OWN sanitizer build (e.g. `make SANITIZER=address`).
  **Use it. Build the whole project ONCE.** This is the expensive step the last run dodged.
- `vocabulary` — the dispatch grammar: `[{ name, handlerSymbol, defFilePath }]` (the command /
  method / subcommand names and where each handler is defined). This is your input alphabet for a
  daemon/CLI — drive these, mutate their arguments, sequence them.
- `subsystems` / `toolchain` / `sanitizeCflags` / `sanitizeEnv`.
Everything runs in a sandbox (Docker `--network none`, or a consented local run) — **offline**.

## The find-loop

1. **Build the whole target under sanitizers.** Run `sanitizerBuild.command`. If it needs tweaks
   (a missing dep, a flag), fix them — this is worth real effort; it is the step that lets you
   reach the real bugs. Only if the project genuinely cannot be built under sanitizers do you fall
   back to a per-subsystem harness — and say so in the draft.
2. **Drive the REAL entry point** (per `programKind`):
   - **daemon** — run the instrumented binary; connect to its protocol socket; send **sequences**
     of commands drawn from `vocabulary`. Reaching a stateful bug needs setup: create the object,
     then operate on it (e.g. an "add to a collection" command, then a "consume the collection"
     command with a crafted count). Seed 1–3 setup ops, then the crafted one. Capture the server's
     stderr — that's where the sanitizer abort prints.
   - **cli** — run the binary with malformed argv flags, stdin, and any input-file argument.
   - **library** — link a thin harness against the built objects that calls the exported API /
     `vocabulary` handler symbols directly with malformed inputs.
3. **Craft inputs at the boundary.** For each command/API: over-long fields, negative/huge counts,
   off-by-one and past-the-limit element counts (a fixed-size stack/heap buffer overflows when the
   count exceeds it), signed/unsigned boundaries, truncated/duplicated structures, deep nesting.
   Mutate counts and lengths first — that is where fixed-buffer overflows live.
4. **Run, read the abort.** On a sanitizer abort, read the report: error class, CWE, the crashing
   frame, and **the whole backtrace** (you need a first-party frame — see step 6).
5. **Escalate the signpost (do not stop at the first crash).** A clean abort or a fixed-offset
   null-deref is a *signpost*, not the prize. Keep varying the same field — boundary, signedness,
   off-by-one, count — to turn it into a controllable out-of-bounds **WRITE** or use-after-free
   before you settle. A bare UBSan signed-integer-overflow with no memory consequence is the
   weakest tier (the finalize will NOT promote it to `proven`) — push it toward a real OOB.
6. **Validate 3/3 and locate in first-party code.** Re-run the crashing input three times; keep
   only crashes that reproduce. Then confirm the crash is reachable from the entry you drove: the
   backtrace must contain a frame in the **target's own source** (a dispatch handler / first-party
   file), not *only* vendored client deps (`deps/…` that you didn't drive), a stub, or your
   harness scaffolding. Minimize the input.

## Output + finalize

Write `{ "discoveries": [{ "title", "language", "subsystem"?, "evidence": [{"filePath","startLine"}],
"preconditions": [...], "accessLevel": "...", "harnessFiles": [{"name","content"}], "buildRunCommand",
"claimedCwe"?, "claimedCrashClass"?, "timeoutMs"? }] }` to the prep's `draftPath`
(`draft.fuzz-discover.json`). `harnessFiles` bakes in everything needed to reproduce — the build, the
driver/script that starts the target and sends the crafted sequence, and the captured-output plumbing;
`buildRunCommand` runs it offline, time-boxed, cwd = the harness dir, and ends by emitting the
sanitizer report on stdout/stderr.

**Your CWE/class claims are advisory only.** `fuzz-discover-finalize` re-runs your `buildRunCommand`
in a fresh sandbox, forces the sanitizer env, and lets `parseSanitizerReport` decide — with two gates
it enforces, not you: (a) the crash must land in **first-party** code reachable from the real entry
(a crash only in vendored deps / a stub / your harness is rejected), and (b) a bare signed-integer
overflow with no memory-corruption consequence is recorded as a `candidate`, not `proven`. A real
OOB-write/UAF/overflow in target code ⇒ a NEW `proven` finding with the sanitizer's exact CWE; a
build failure ⇒ `harness-failed-build`; a clean run ⇒ `not-reproduced`. You cannot talk a crash into
existence, and you cannot promote a vendored-leaf crash — only a reproducing abort in the real target.

### Derived-severity inputs
Don't assert a severity — the finalize derives it (`scripts/lib/severity.mjs`). Emit `preconditions: []`
(every condition needed to reach the crash: e.g. `"the target key/object must already exist"`,
`"an authenticated connection"`) and `accessLevel` (minimum attacker access:
`unauthenticated-remote` / `authenticated` / `local-only`). The crash's memory class drives the rest.

## Non-crash classes — invariant oracles

Some real bugs emit NO sanitizer abort (prototype pollution, global/class corruption). They are
still in scope through a **framework-owned invariant oracle**: you DECLARE the target, the
framework drives standard payloads and checks the broken invariant. When `prep.json` lists
`oracleTargets` (e.g. a JS package → `prototype-pollution` / CWE-1321), emit an oracle discovery —
NO harness code, NO buildRunCommand:

    { "oracle": "prototype-pollution", "targetModule": "<the package entry, e.g. index.js>",
      "inputShape": "argv-array" | "merge-object" | "json-parse" | "query-string" | "auto",
      "evidence": [{ "filePath": "<the polluting sink>", "startLine": N }],
      "preconditions": [...], "accessLevel": "..." }

The finalize runs the framework oracle against your declared target and trusts ONLY its marker —
you cannot fake it (it fires only if the prototype is actually polluted). Pick `inputShape` from how
the entry takes input (an argv array, an object it merges, a JSON string it parses, a query string);
`auto` tries all. Anchor `evidence` to the sink that writes the attacker-controlled key.

## When NOT to use

- To PROVE an already-found memory finding from a harness — that's `/sanitize-pov` (it starts from a
  finding; you start from nothing).
- When code execution isn't acceptable, or no sandbox/toolchain/buildable target is available —
  report the skip.
- For a non-crash class with NO oracle yet — prototype pollution has a framework oracle (above), but
  authorization / business-logic flaws need a differential oracle that isn't wired here yet; don't
  force a sanitizer crash for them — report the skip rather than a false proof.
- To grade exploitability or write a fix — that's `/mem-exploitability` and `/fix`.

## Rationalizations to Reject

- *"This vendored parser is the only thing that builds standalone, so I'll fuzz it."* → That is the
  exact retreat that wasted the last run on a benign vendored bug. Build the WHOLE project with its
  own sanitizer build and drive the real entry; the real bugs are in the handlers, not the bundled
  client.
- *"It didn't crash quickly, so the code is safe."* → Absence of a crash in a short run is not proof
  of safety. Drive the real commands with stateful setup + boundary counts before concluding clean.
- *"A leaf function aborts under ASan — promote it."* → If the only backtrace frames are vendored
  deps / a stub / your harness, it is not reachable from the real entry and the finalize rejects it.
  Reach it through the entry you drove.
- *"It crashed once — promote it."* → Validate 3/3. A one-off is noise; the finalize records
  `not-reproduced`.
- *"A clean abort / null-deref / signed-overflow is the bug."* → Those are the weak tier. Escalate
  toward a controllable OOB-write/UAF on the same path; a bare integer-overflow is recorded as a
  candidate, not proven.
- *"I'll claim CWE-787 since it looks like an overflow."* → Don't assert the class; the finalize's
  sanitizer report sets it. Your job is a reproducing input through the real entry, not the verdict.

## Reference the non-findings taxonomy (drop these before promoting)

Record `exclusionRule` + `refuteReason` and do NOT submit:
- **#2 Test / fixture / scaffolding** — a crash in a `*_test`, an example, a stub you wrote, or your
  own harness is not a target bug.
- **#9 Client-class on the server** (and vice-versa) — a crash in a bundled *client* library
  (outbound RESP, a cluster-bus client) reached from a standalone harness, when the CVE surface is
  the server's request path, is off-target.
- **#1 Volumetric DoS / allocator** — `allocation-size-too-big` from simply requesting a huge size,
  with no overflow/corruption, is not a finding here.

## Worked example (daemon, stateful command bug)

A daemon's `prep.json` has `programKind: "daemon"`, `sanitizerBuild.command: "make SANITIZER=address -j"`,
and a `vocabulary` including `{name:"thing.add", handlerSymbol:"thingAddCommand"}` and
`{name:"thing.consume", handlerSymbol:"thingConsumeCommand", defFilePath:"src/t_thing.c"}`.

1. **Build & run** — `make SANITIZER=address -j`, then `./bin/server --port 7777 2> asan.log &`.
2. **Reasoned classification** — `thingConsumeCommand` takes a caller-supplied **count** of IDs into a
   fixed buffer. Hypothesis: a count past the buffer size is an OOB write. It only runs once the
   object exists (a `!object` guard returns early otherwise) → **stateful-shallow, 1 setup op**.
3. **Drive the real protocol** — seed state, then cross the boundary:
   `client -p 7777 thing.add k field val` ; `client -p 7777 thing.consume k COUNT 9 id1 id2 id3 id4 id5 id6 id7 id8 id9`
   (9 > the fixed buffer of 8). ASan aborts in `asan.log` with a stack-buffer-overflow whose
   backtrace includes `t_thing.c` (first-party — passes the gate).
4. **Validate 3/3, minimize** (drop to the minimal id count that still overflows), **emit the draft**:

```json
{ "discoveries": [{
  "title": "stack-buffer-overflow in thingConsumeCommand via past-limit COUNT",
  "language": "c",
  "evidence": [{ "filePath": "src/t_thing.c", "startLine": 3538 }],
  "preconditions": ["the target object must already exist (1 setup command)"],
  "accessLevel": "authenticated",
  "harnessFiles": [{ "name": "run.sh", "content": "#!/bin/sh\nmake SANITIZER=address -j >/dev/null 2>&1\n./bin/server --port 7777 2>asan.log &\nP=$!; sleep 1\n./bin/client -p 7777 thing.add k f v\n./bin/client -p 7777 thing.consume k COUNT 9 1 2 3 4 5 6 7 8 9\nsleep 1; kill $P 2>/dev/null; cat asan.log" }],
  "buildRunCommand": "sh run.sh"
}] }
```

The finalize re-runs `sh run.sh`, sees the stack-buffer-overflow with a `t_thing.c` frame, derives
severity from `accessLevel`+`preconditions`+class, and promotes a `proven` CWE-121 finding.
