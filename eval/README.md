# LLM-in-the-loop eval (`npm run eval` / `eval:cve`)

The first **valid** measurement of kuzushi's bug-finding. Everything else in this repo
that looked like a test was not:

- `npm test` — unit tests of the deterministic scripts.
- `npm run bench` / `bench:cve` — only the deterministic *prepare* phase; **no LLM**.
- Earlier "blind CVE" demos — the agent drafts were **hand-authored by a human**, so
  they measured the human, not the plugin (and were contaminated by foreknowledge).

This harness runs the **real agents** (`deep-scanner`, `verifier`) in fresh
`claude -p` sessions and scores them blind.

## How it works

kuzushi's agents are prose interpreted by a Claude session — there is no programmatic
agent runner. So the harness reproduces the live skill's boundary exactly:

```
deep-scan-prepare (deterministic, here)
   → claude -p as the deep-scanner  (agents/deep-scanner.md = its system prompt)
deep-scan-finalize (deterministic, here)
   → verify-prepare (deterministic, here)
   → claude -p as the verifier
   → verify-assemble (deterministic, here)
   → score findings.json vs the case's expected.json
```

`eval/run-agent.mjs` is the single LLM integration point: it spawns
`claude -p "<task>" --append-system-prompt <agent.md> --add-dir <repo>
--plugin-dir <plugin> --dangerously-skip-permissions --model <m> --output-format json`.
The agent's deliverable is the **draft file** it writes; the harness runs the
deterministic finalize on it.

**Blind by construction:** the case repo is copied to a scratch tmp dir with **no
`expected.json` sibling**, and the agent is told not to look for answer files. It
cannot see the ground truth.

## What's measured

Per case (averaged over `--reps`):

- **routed** — the deep reader's prep put the vulnerable file in the read set. A
  ranking/coverage check (precondition for finding anything).
- **found** — a `deep-scan` finding landed on the expected file (±6 lines). The
  reasoning-level recall.
- **confirmed** — the verifier called that finding `confirmed-exploitable`. Precision
  signal.
- **extra-confirmed** — confirmed findings *not* matching the expected anchor (a
  false-positive proxy; caveat: a single-CVE repo may contain other real bugs).

A **low number is a valid, honest result** — the baseline the capability levers must
beat. The harness exits non-zero only on its own failure, never on a low score.

## Two lanes: `deep-scan` (default) and `deep-hunt`

`--mode deep-scan` (default) measures the **whole-file reader**. `--mode deep-hunt`
measures the **interprocedural hypothesis hunt**: it anchors trace points (entry points
+ dangerous sinks), runs the real `deep-hunter` agent to **walk source→sink across
files** (via the `callees`/`callers` CLIs), finalizes, then verifies — scoring on the
same corpus so the two recall lanes are directly comparable. The deep-hunt scoreboard
adds a **`cross-file`** column: of the runs that *found* the bug, how many did so with a
flow spanning **≥2 files** — the recall same-file taint and pattern-gating can't produce.
A found/hit is any evidence anchor **or path node** landing on the expected line (±6), so
a cross-file flow isn't scored a miss when the planted line is the sink, not the source.

## Running

```
npm run eval                       # deep-scan lane, synthetic cases (bench/cases/*)
npm run eval -- --case hidden-tenant --model sonnet --maxFiles 8
npm run eval:cve                   # deep-scan lane, real CVEs (fetch bench/cves/<id>/fetch.sh first)

npm run eval:deep-hunt             # deep-hunt lane, synthetic cases
npm run eval:deep-hunt:cve         # deep-hunt lane, real CVEs  → eval/scoreboard.deep-hunt.cve.md
npm run eval:deep-hunt:cve -- --model sonnet --reps 3 --maxAnchors 24
```

Flags: `--mode` (`deep-scan` | `deep-hunt`), `--model` (sonnet|opus|…), `--reps`
(runs/case), `--maxFiles` (deep-scan read budget), `--maxAnchors` (deep-hunt anchor
budget), `--case <name>` (one case), `--cve`. Scoreboards are lane-specific:
`scoreboard[.deep-hunt][.cve].md`. Needs `claude` on PATH and an authenticated session;
each run is billed (the scoreboard reports total cost). The cross-file CVE lane is the
one that proves L1–L4 moved the number — run it where deep-scan's baseline missed (e.g.
the Redis XACKDEL case, a routing/cross-file miss at 33%).

> **Not a CI gate — by design.** This eval is billed, nondeterministic, and
> minutes-to-hours long, so it is **never** part of `npm test` / the GitHub `test`
> workflow. The deterministic suite (`npm test`) is the gate that blocks regressions;
> this eval is the manual instrument you run by hand to *move* the find-rate. A low
> eval number is a real result, not a build failure.

## Results log

- **Harness validation (synthetic `hidden-tenant`, Sonnet, 1 run):** routed/found/
  confirmed = 100% at $0.42 — the real deep-scanner found a tokenless broken-tenant
  -isolation bug blind and the real verifier confirmed it. Proves the instrument.
- **CVE BASELINE (Sonnet, 1 run/case, maxFiles 10, $3.48)** — real agents, blind:

  | Case | routed | found | confirmed | FP-proxy |
  |---|---|---|---|---|
  | minimist CVE-2020-7598 (proto pollution) | ✅ | ✅ | ✅ | 0 |
  | redis CVE-2025-49844 (Lua RCE) | ✅ | ❌ | ❌ | 1 |
  | redis CVE-2025-62507 (XACKDEL overflow) | ❌ | ❌ | ❌ | 1 |
  | **overall** | **67%** | **33%** | **33%** | |

  Honest read: blind find-rate is **33%**, with false positives on the two Redis
  cases. The misses are diagnostic and match the manual analysis exactly:
  - XACKDEL — *routing* failure: the deep reader never put `t_stream.c` in the read
    set (keyword ranking didn't prioritize it). → Phase 2 (reachability ranking).
  - Lua RCE — *reasoning* failure: routed to `lparser.c` but missed the subtle
    GC use-after-free and emitted a different (FP) finding. → Phase 4 (methodology),
    Phase 5 (panel to refute the FP).

- **Lever re-measure (Sonnet, 1 run, maxFiles 30, $9.24)** — the harness earning its
  keep by refuting a false "improvement":

  | Case | baseline (maxFiles 10) | after levers (maxFiles 30) |
  |---|---|---|
  | minimist | routed/found/confirmed ✅ | ✅ |
  | redis Lua RCE | routed ✅ · found ❌ | routed ❌ (regressed) · found ❌ |
  | redis XACKDEL | routed ❌ · found ❌ | routed ✅ (fixed) · found ❌ |
  | **overall** | 67 / **33** / 33% | 67 / **33** / 33% |

  The levers **did not improve blind find-rate** (still 33%) and the reachability
  ranking *regressed* the Lua case: entry-point density over-favored first-party
  `*Command` files and pushed the vendored Lua parser out of the budget. Without this
  harness that would have shipped as a "win."

- **Ranking-regression fix (deterministic, no LLM cost):** added an `input-processor`
  signal (parser/lexer/decoder/deserializer/VM) so attacker-data surfaces reached via
  APIs keep real weight. Verified on the real repos at maxFiles 30: **both** files now
  route — `lparser.c` #26, `t_stream.c` #21 → routing is now **3/3**. (Re-running the
  full LLM eval to reconfirm costs ~$9; deferred — routing is verified deterministically.)

- **Opus re-measure (Opus, 1 run, maxFiles 30, $22.31):**

  | Case | routed | found | confirmed | FP-proxy |
  |---|---|---|---|---|
  | minimist | ✅ | ✅ | ✅ | 0 |
  | redis Lua RCE | ✅ | ❌ | ❌ | 1 |
  | redis XACKDEL | ✅ | ❌ | ❌ | 0 |
  | **overall** | **100%** | **33%** | **33%** | |

  Two findings: (1) **routing is now 100%** end-to-end (the input-processor ranking fix
  confirmed live — both Redis files reached). (2) **Model strength is NOT the
  bottleneck** — Opus, reading the right files, still missed both Redis bugs blind. The
  Lua GC-UAF needs a deep Lua-internals rooting invariant; the XACKDEL stack overflow
  sits at line ~3537 in a 3,500-line file and was missed *despite correct routing* — a
  breadth-vs-depth signal (30 whole files ⇒ shallow per-file attention).

- **Where this leaves parity (no spin):** routing = solved; reasoning-level find on
  subtle memory bugs is **not**, and a Sonnet→Opus swap did not move it (find-rate flat
  at 33%, the minimist case). The next experiment the harness points to is **depth**
  (few files, read deeply, multi-pass) rather than more files or a bigger model — and an
  honest possibility is that some of these (the Lua GC-UAF) are at/over the edge of
  reliable one-pass blind discovery for current models. The value delivered is the
  measurement loop itself: every claim here is a reproducible `npm run eval:cve` number,
  not an assertion.

  Spend so far across all eval runs: ~$35 (Sonnet baseline $3.48 + lever re-run $9.24 +
  Opus $22.31, plus a synthetic validation $0.42).

- **DEPTH is the lever (focused experiment, Sonnet, $1.79):** deep-reading **only**
  `src/t_stream.c` (via the new `--files` focus), the *same Sonnet* that missed the
  XACKDEL overflow among 30 files **found it and the verifier confirmed it** — found
  100%, FP 0. The bottleneck was attention dilution, not model strength or routing.
  Caveat: that run *named* the file (ground-truth file selection), so it proves
  "depth-given-routing," not blind end-to-end.

- **Blind batched re-run (Sonnet, maxFiles 25, batch 5, $8.44): routed 100%, found 0%.**
  Reading the routed files in 5-file deep batches — blind, no file named — did **not**
  recover the XACKDEL find, even though reading `t_stream.c` *alone* did. So the depth
  effect is real but **steep**: the effective batch size for this bug is ~1 file, which
  doesn't scale (25 files ⇒ 25 separate agent passes), and the single-file success is
  n=1 and may be partly variance.

- **Bigger corpus + a measurement-validity bug it exposed (no headline number yet).**
  The CVE corpus was expanded from 3 to **9 real cases** (minimist + 8 fix-derived Redis
  CVEs: lbaselib int-overflow, llex OOB, config authz, blocked UAF, replication UAF, rdb
  overflow, plus the existing Lua-RCE and XACKDEL). The first big run (`eval:cve`, Sonnet,
  maxFiles 10) was **aborted as invalid**: real Redis cases hit the per-agent **15-min
  `spawnSync` timeout BEFORE writing a draft** — scored as `found=false, $0.00` (a killed
  `claude -p` emits no cost JSON, but the tokens were spent). Root cause: the deep-scanner
  methodology has since expanded (per-obligation tree-sitter + concolic + LSP on *every*
  file), so a 10-file real repo no longer finishes in 15 min — the old run that did was a
  lighter agent. This is a harness-validity bug, not a find-rate: a timeout ≠ a miss.
  **Fix (landed):** `--timeoutMs` is now configurable (default raised to 30 min) and the
  scoreboard header records it. **Validated** with a single-case smoke (`redis-cve-2026-23479`,
  Sonnet, maxFiles 6, 30-min cap, **$3.62**): the case ran end-to-end — draft written, verifier
  ran and confirmed a finding — instead of an empty timeout. The harness-validity bug is fixed.

- **What the smoke then exposed: routing, not reasoning or timeout, is the limiter on this
  harder corpus.** The smoke scored `routed=0` because the bug file ranked outside maxFiles 6.
  A free deterministic rank survey (no LLM — `deep-scan-prepare` only) of where each bug file
  lands in the risk ranking:

  | case | bug file | rank | routed@6 | @10 | @30 |
  |---|---|---|---|---|---|
  | 46817 | `deps/lua/src/lbaselib.c` | **not in top 80** | n | n | n |
  | 46818 | `src/config.c` | 8 | n | ✅ | ✅ |
  | 46819 | `deps/lua/src/llex.c` | 29 | n | n | ✅ |
  | 49844 | `deps/lua/src/lparser.c` | 25 | n | n | ✅ |
  | 62507 | `src/t_stream.c` | 21 | n | n | ✅ |
  | 23479 | `src/blocked.c` | 31 | n | n | n |
  | 23631 | `src/replication.c` | 16 | n | n | ✅ |
  | 25243 | `src/rdb.c` | 34 | n | n | n |

  Routing rate: **0/8 @6, 1/8 @10, 5/8 @30.** So `maxFiles 6` was the *wrong* re-run
  recommendation (0% routing); and the only budget that routes a majority (30) brings back the
  timeout, craters per-file depth (the breadth-kills-depth result above), and costs ~$15+/case
  (~$120 for the corpus). One file (`lbaselib.c`) doesn't rank at all. **Conclusion:** the
  earlier "routing solved (100%)" was overfit to the original 3 cases; on this harder 8-CVE set
  the deterministic ranking surfaces bug files at ranks 16–34 (or not at all), so a *blind*
  9-CVE find-rate would mostly measure ranking quality at a budget where depth is already lost.
  The honest headline below stays the **3-CVE** number; the real lever this surfaces is
  **risk-ranking recall** (why core sinks like `blocked.c`/`rdb.c` and the vendored
  `lbaselib.c` rank low), measurable for free before any further billed run.

### Bottom line (honest, after ~$49 of real runs)

The plugin's **blind find-rate on this 3-CVE set is ~33%** (only minimist; both Redis
bugs unfound blind across Sonnet-30, Opus-30, and Sonnet-batch-5). What moved:
- **Routing: solved *on the original 3 cases* (100% at maxFiles 30), but NOT general.**
  The 8-CVE rank survey above shows bug files landing at ranks 16–34 (one unranked), i.e.
  routing was overfit to those 3 — risk-ranking recall is the next real lever, not a
  closed item.
- **Reasoning: not solved.** Not by a bigger model (Opus = no change), not by simple
  depth-batching (batch-5 = no change). Only a single-file read found the tractable bug,
  and that's both unscalable and statistically thin (n=1).

This is **not parity with Xint** on blind *static* discovery, and the harness is what lets
us say so with evidence instead of vibes. The remaining gap is reasoning-at-scale on subtle
memory bugs by *reading*.

**But the empirical path closes it for the proof half.** Rather than out-read the bug, we
borrowed the AIxCC core — prove it by *running* under sanitizers (`/sanitize-pov`,
`scripts/lib/sanitizers.mjs`). Validated end-to-end on **real Redis CVE-2025-62507**: built
the target with its own `make SANITIZER=address`, sent `XACKDEL … IDS 9 …`, AddressSanitizer
aborted with `stack-buffer-overflow` in `xackdelCommand`, the oracle mapped it to CWE-121,
and the finding was promoted to `proven` (CWE sharpened from a seeded vague CWE-119). The bug
the static reader missed at breadth is **proven by execution** — ~10 min, ~½ GB, no network.
So: static blind-discovery ≈ 33% (honest, low); empirical proof of a real memory CVE = works.
The enduring deliverables are the **measurement loop** and the **sanitizer oracle** — not a
parity claim on raw discovery, which still wants a fuzzing fleet kuzushi doesn't have.
