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

- **Lever deltas:** recorded here as each lands (re-run `npm run eval:cve`).
