# Real-CVE run — honest results

Cases are real public CVEs in widely-analyzed projects (Redis), plus minimist. Ground truth in each `expected.json` is derived from the
actual upstream **fix commit** (not memory): the case fetches the source at the
fix's *parent* (vulnerable) commit, and the changed file:line is the truth.

> Cloud-SAST vendors' *specific* 0days aren't published with a verifiable file:line, and blind-
> rediscovering a real 0day in a million-LOC tree in a shell session isn't realistic.
> These are the verifiable proxy: real disclosed CVEs in the same codebases, run
> blind, scored against the real fix.

## Two distinct metrics — don't conflate them

1. **File-routing recall** (what `npm run bench:cve` measures, no LLM): did some
   producer's deterministic prepare surface the vulnerable file at all? This is a
   precondition for finding the bug, not the find itself.
2. **Reasoning-level find** (needs the LLM in the loop): given the routed file, does
   the deep-scanner actually identify the real bug, and does the panel confirm it?
   Measured by hand below.

## File-routing recall — `npm run bench:cve`

| Case | vulnerable file | routed? |
|---|---|---|
| minimist CVE-2020-7598 (proto pollution) | `index.js` | yes |
| redis CVE-2025-49844 (Lua RCE) | `deps/lua/src/lparser.c` | yes (taint-analysis @ deps) |
| redis CVE-2025-62507 (XACKDEL stack overflow) | `src/t_stream.c` | yes (sharded sweep) |

3/3 routed. Note: `/deep-scan` *alone*, whole-repo, ranked `lparser.c` #8/794 (its
path matched the "parser" risk heuristic) but did **not** rank `t_stream.c` within a
60-file budget — the sharded `/sweep` is what reached `t_stream.c`. So routing depends
heavily on sharding + the risk heuristics; on a huge repo with a tight budget, a file
with no ranking signal can be missed.

## Reasoning-level find — the blind test (the honest part)

**minimist CVE-2020-7598 — FOUND (but not blind).** Read `index.js`, identified the
unguarded `__proto__` write in `setKey()`, panel-confirmed `CWE-1321`. Exact match to
ground truth. Caveat: this CVE is well-known; I recognized it. Not a blind find.

**redis CVE-2025-49844 (Lua RCE) — MISSED, blind.** deep-scan routed to the right
file (`lparser.c`) and I read it without looking at the fix. I formed a concrete,
falsifiable hypothesis — *unbounded recursion in the recursive-descent parser →
stack overflow → RCE* — and it was **wrong**. The real bug is a **use-after-free**:
the chunk-name `TString` from `luaS_new` wasn't anchored on the Lua stack during
parsing, so GC could free it mid-parse (the fix adds `incr_top` / `--L->top`). I
pattern-matched to the common "parser depth" bug class; the actual flaw needs deep
knowledge of Lua's GC rooting invariants. Right file, wrong mechanism.

## Honest verdict

- The machinery works: sweep + sharding routes to real vulnerable files (3/3), and
  the deep-reader → panel pipeline produces verified findings on real third-party
  code (minimist).
- **It is not yet at cloud-SAST level on raw bug-finding power against real targets.** On
  the one genuinely-blind subtle CVE tested (Redis Lua RCE), it reached the file but
  did not identify the bug. The limits are concrete: (a) the risk-ranker is heuristic
  and budget-bounded, so the right file isn't guaranteed to be read on a large repo;
  (b) one-pass blind identification of a subtle memory/GC bug is unreliable.
- So the README/docs wording stays **"closing the gap," not "closed."** Closing it
  for real means: stronger reachability-driven ranking (build code-graph/CPG first),
  a larger read budget, and multi-pass deep reading — and a broader blind CVE set
  (more projects, scored find-rate + false-positive-rate) before any parity claim.

_To reproduce: `bash bench/cves/<id>/fetch.sh` then `npm run bench:cve`. Fetched
sources are gitignored; `fetch.sh` + `expected.json` are committed._
