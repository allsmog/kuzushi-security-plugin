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

## Running

```
npm run eval                       # synthetic cases (bench/cases/*)
npm run eval -- --case hidden-tenant --model sonnet --maxFiles 8
npm run eval:cve                   # real CVEs (fetch bench/cves/<id>/fetch.sh first)
npm run eval:cve -- --model sonnet --reps 3 --maxFiles 12
```

Flags: `--model` (sonnet|opus|…), `--reps` (runs/case for variance), `--maxFiles`
(deep-scan read budget), `--case <name>` (one case). Needs `claude` on PATH and an
authenticated session; each run is billed (the scoreboard reports total cost).

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

### Bottom line (honest, after ~$49 of real runs)

The plugin's **blind find-rate on this 3-CVE set is ~33%** (only minimist; both Redis
bugs unfound blind across Sonnet-30, Opus-30, and Sonnet-batch-5). What moved:
- **Routing: solved** (100%, reachability + input-processor ranking, confirmed live).
- **Reasoning: not solved.** Not by a bigger model (Opus = no change), not by simple
  depth-batching (batch-5 = no change). Only a single-file read found the tractable bug,
  and that's both unscalable and statistically thin (n=1).

This is **not parity with Xint**, and the harness is what lets us say so with evidence
instead of vibes. The remaining gap is genuine reasoning-at-scale on subtle memory bugs;
plausible next directions (each a measurable `npm run eval:cve` experiment, none yet
proven): a **structured per-function pass** that forces enumerate-every-fixed-buffer-and-
check-bounds rather than free reading; **repeated sampling** (k runs/file, union) to beat
variance; and a **larger CVE corpus** scored for find-rate *and* FP-rate. The deliverable
that endures is the measurement loop, not a parity claim.
