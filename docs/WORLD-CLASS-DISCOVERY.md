# Roadmap: world-class bug discovery

This is the plan to close the gap between kuzushi's **proof** rigor (already strong) and
its **discovery** power (good, not world-class). It is written to one rule: **no false
wins.** Every phase has a *free* deterministic gate that must pass before any billed run,
a *billed* validation that must move a real number, and an explicit **kill criterion** —
the result that tells us to stop, not to spin. A phase that fails its gate is reported as
a negative result, not quietly dropped.

## What "world-class" means here (the bar)

Two axes, both required — being elite on one while weak on the other is not world-class:

1. **Recall** — blind find-rate on a held-out, real-CVE corpus, competitive with an
   AIxCC-class cloud CRS / GHAS+CodeQL at scale on a comparable set.
2. **Precision / proof** — low false-positive rate and ~zero false *proofs* (a `proven`
   verdict on a non-bug). This is the defender-value contract in `BENCHMARKS.md`.

**Concrete exit target** (proposed, falsifiable): on a ≥20-case real-CVE corpus spanning
memory + web + logic classes, **blind find-rate ≥ 60%** with **proven-on-target ≥ 40%**,
**false-proof rate = 0**, and **extra-confirmed (FP-proxy) ≤ 1 per case** — reproducible
via `npm run eval:cve`. Today's measured baseline is **22% found / 22% confirmed** on the
9-CVE set (Sonnet, $43.51). The target is deliberately a number we can be held to.

## The terrain (measured this session, not assumed)

Discovery splits into three tiers; one knob (the file ranker) cannot serve all three, and
trying to make it is the documented false-win trap (`eval/README.md`).

- **Tier 1 — cheaply routable.** Entry points, dispatch handlers, high-reach core, input
  processors. File-ranking already works: on real redis, `config.c` #7, `rdb.c` #23,
  `t_stream.c` #27. **Solved.**
- **Tier 2 — no static signal, but fuzz-reachable memory bugs.** Belongs to the execution
  lane (`/sanitize-pov` proves, `/fuzz` discovers), which doesn't route at all — it builds
  with sanitizers and *runs*. Proven on the real `xackdel` overflow. **Architecturally
  solved; not yet run at scale.**
- **Tier 3 — no static signal AND not fuzz-reachable.** The Lua int-overflows (need ~2 GB
  input, UB/`-O`-gated), the lifecycle UAFs. Neither ranking nor small-input fuzzing
  reaches these. **The unsolved tier.**

And "read-and-missed" (the Tier-3 wall) decomposes into **three failure modes**, each
measured on real CVE files and each needing a different fix:

| Mode | Symptom (measured) | Fix lane |
|---|---|---|
| **A — noise** | `lbaselib.c`: 203/204 obligations were `lua_*` accessor noise | de-noise the taxonomy (**done** — 204→31, −85%) |
| **B — coverage gap** | `blocked.c` / `replication.c` / `rdb.c`: **no obligation at the bug site** | extend lifetime/OOB rules, gated on noise |
| **C — reasoning** | `lparser.c`: correct obligation *on the bug line*, still missed | per-class specialist reasoning + execution |

## Phases (ordered by leverage-per-dollar)

### Measured this session (billed + free)
- **Billed harness check ($0.71, Sonnet, `native-uaf`):** routed 100% / found 100% /
  confirmed 0%. The deep-scanner finds the synthetic UAF **blind** with the de-noised
  obligations. `confirmed 0%` is **Lever-2 working as designed** — memory findings now route
  to the execution lane, so the read+verify lane no longer "confirms" a UAF by reading; that
  metric moves to `proven` via the discover/`sanitize-pov` lane. Measurement interaction to
  remember: score memory classes by `proven` (discover lane), not `confirmed` (verify lane).
- **Light CPG validated (free).** A *scoped* CPG of one subsystem (`deps/lua/src`, 38 files)
  builds in **6 s** (vs minutes whole-repo) and queries run in seconds — laptop-tractable.
  The "heavy CPG" I'd deferred was the wrong framing; **scoped CPG is the answer** for the
  cross-function memory lane.
- **Two real query bugs found + one fixed (free).** (1) Joern's `.code()` is a FULL-match —
  the starter queries' patterns silently under-matched until wrapped in `.*…​.*` (int-overflow:
  0 → 25 flows). (2) The queries were C-idiom-only; adding Lua-aware terms (`luaL_optint`,
  `lua_checkstack`, `luaM_*`) made int-overflow function on Lua code. The `use-after-free`
  query finds real `free()`-based flows but **cannot see a GC-collection UAF** (`lparser`) —
  that's not a `free()`, so it likely needs GC-model awareness or is out of CPG-dataflow reach.
- **SCALABLE scoped-CPG lane built + it reaches a Tier-3 bug (free).** `scripts/lib/scoped-cpg.mjs`
  + the `cpg-scan` CLI: scope-select (subsystem dir or caller/callee closure) → build a bounded
  CPG → run the memory queries, in one call. Build cost scales with the **scope**, not the repo,
  so it runs on any repo size. **Measured win:** `cpg-scan --file deps/lua/src/lbaselib.c
  --query int-overflow` builds in ~6 s and surfaces the **CVE-2025-46817 flow** (source L346
  `luaL_opt` → sink L349 `lua_checkstack`) — the int-overflow that file-routing ranked #606 and
  the eval declared no static lane could reach. First time a Tier-3 "no-signal" bug is reached
  by a static lane. Wired into the deep-scanner prose; joern-gated tests pin it.

**Course-correction to the bar:** Phase 2's honest scope is now "the scoped-CPG dataflow lane,
idiom-aware per target." It demonstrably reaches the *integer-overflow* Tier-3 class; the
*GC-collection UAF* class (`lparser`) remains beyond it (no `free()` edge) and stays Phase-4's
(execution) or an explicit out-of-static-reach. **Auto-wiring landed:** `verify-prepare` now runs the scoped-CPG lane automatically for every
memory-class candidate and attaches the interprocedural flows as `cpgLeads` (joern-gated,
bounded, deduped) — the verifier consumes them without the agent invoking `cpg-scan` by hand.
Validated: a CWE-190 finding on `lbaselib.c` auto-gets the 345→349 flow; a CWE-89 finding gets
none. The remaining open item is a **billed eval** to confirm the full lead→verify→proof chain
moves the find-rate on the real CVE corpus.

### Phase 0 — Re-measure the honest baseline *(prerequisite, billed ~$45)*
You cannot roadmap from a stale number. This session changed obligations, ranking,
dispatch, and the verifier; none is validated end-to-end.
- **Build:** none — run `npm run eval:cve` (9-CVE, Sonnet, maxFiles 30) and
  `eval:deep-hunt:cve` with the current tree.
- **Free gate (done):** unit suite green (303/0); free rank + obligation surveys recorded.
- **Billed gate:** record found/confirmed/FP per case vs the 22% baseline.
- **Kill criterion:** if the number *regressed*, a this-session change is net-negative —
  bisect and revert before building anything new.

### Phase 1 — Obligation-routed sweep *(the architectural lever)*
Stop ranking files and reading top-N whole; **enumerate obligations repo-wide and
discharge them function-scoped, in budget order.** This attacks the wall on three fronts at
once: it sidesteps routing (an obligation in file #606 is still in the pool), multiplies
throughput (read 20-line functions, not 3,000-line files), and *is* the methodology that
flipped `xackdel` from unfindable to found.
- **Build:** a discovery mode in `deep-scan-prepare`/sweep that emits an obligation
  worklist (file, line, kind, enclosing-function span) ranked by a discharge-priority
  score (class severity × attacker-reachability × novelty), budgeted by *obligation count*
  not file count. The agent discharges each in its enclosing-function scope.
- **Free gate:** on the fetched CVE repos, the bug-site obligation must survive into the
  top-N discharge budget for the Mode-A/C files (`lbaselib`, `lparser`, `t_stream`).
  De-noise (done) is the prerequisite that makes this possible.
- **Billed gate:** find-rate on the 9-CVE set **beats Phase 0** at equal or lower $/case.
- **Kill criterion:** if obligation-routing doesn't beat file-routing on find-rate, the
  throughput multiplier is illusory — say so; the lever is the cloud throughput lane, not this.

### Phase 2 — Mode-B sites → the CPG dataflow lane *(re-scoped after measurement)*
**Measured course-correction (do not skip this — it killed the obvious plan).** The first
Phase-2 hypothesis was "extend the regex obligations to cover the no-obligation bug sites."
Reading the actual Mode-B sites refuted it: `blocked.c:699` is a UAF where the free happens
*inside a callee* (`processCommandAndResetClient(c)`) and `c` is used after — there is no
`free()` on any line a regex sees; `replication.c`/`rdb.c`/`llex.c` patch lines are
arithmetic/logic, not dangerous-primitive shapes. These are **cross-function / interprocedural
lifetime bugs**. A regex obligation cannot catch them, and widening it to try would be the
catastrophic-noise false win this roadmap forbids.

So Mode-B memory bugs belong to the **CPG dataflow lane**, not regex obligations:
- **Build:** route memory-class discovery through the Lever-3 starter Joern queries
  (`use-after-free.sc`, `double-free.sc`, `integer-overflow.sc`) against the auto-built CPG,
  and feed their hits into the findings index as leads (same shape as a taint flow). The
  regex obligation lane keeps the *intraprocedural* sites it does well (the `t_stream` buffer,
  the `lparser` gc-rooting); the CPG owns the cross-function ones.
- **Free gate:** build the CPG for a fetched memory CVE repo and confirm the UAF query
  surfaces (or provably cannot surface, with the reason) each Mode-B bug — *unverified as of
  this writing; it is the next measured experiment* (a redis CPG build is heavy, deferred).
- **Billed gate:** ≥1 Mode-B CVE flips to found via the CPG lead → verify.
- **Kill criterion:** if the CPG query can't reach a cross-function UAF either (its
  `reachableByFlows` heuristic is imperfect), that bug is the execution lane's (Phase 4) — or
  honestly out of static reach. State it; don't widen a regex to fake coverage.

### Phase 3 — Mode-C: class-specialized reasoning *(the L6 lever)*
For sites where the obligation is correct and reasoning still fails (`lparser` GC-UAF):
dedicated per-class methodology, not a generic reader. UAF/lifetime, deserialization
gadget-chains, TOCTOU/races, integer-overflow→OOB, type confusion — each as a focused
discharge procedure (and, where it earns its keep, a forked specialist agent) that knows
the class's invariant and the standard ways it's violated.
- **Build:** extend the per-class discharge procedures (already in `deep-scanner.md` for
  memory/lifetime/arithmetic/injection/authz) into deeper, class-specific playbooks; add a
  lifetime/GC-rooting specialist lens that traces alias sets and allocation-trigger calls.
- **Free gate:** the specialist, given the routed file, names the correct invariant on the
  fixture cases (`native-uaf`) deterministically where possible.
- **Billed gate:** ≥1 of the routed-but-missed lifetime CVEs (`lparser`, `blocked`,
  `replication`) flips to found.
- **Kill criterion:** if a focused, file-named specialist pass *still* misses the GC-UAF,
  that class is at/over the edge of reliable blind static discovery — it is Tier-2/4's job
  (run it), and we stop claiming static reading will get it.

### Phase 4 — Execution-grounded discovery at scale *(the Tier-2 lever)*
The routing-independent lane: find memory bugs by *running* under sanitizers, no ranking
required. Architecture exists (`/fuzz` + `fuzz-discover`, `/sanitize-pov`, the Lever-2
feedback loop); what's missing is **scale and the unrun merge gate**.
- **Build:** wire coverage-guided generation to the discover daemon path; automate the
  minimizer execution in-sandbox; close the corpus-evolution loop.
- **Free gate:** the discover recon surfaces a buildable target + seed for the memory CVEs;
  sanitizer oracle classifies a planted abort deterministically (already unit-tested).
- **Billed gate:** **`npm run eval:discover:cve` — the unrun merge bar — ≥ 3/6 memory
  cases proven** by a real sanitizer abort. This is the single most credible discovery
  number kuzushi can produce, because a sanitizer abort is ground truth, not a judgment.
- **Kill criterion:** cases that don't crash under a time-boxed campaign are honestly
  reported as out of laptop reach (the 2 GB-input Lua overflow likely is) — not hidden.

### Phase 5 — Ensemble discovery + adversarial cross-validation *(recall + precision together)*
Bring panel-mode thinking to discovery (it exists only at verify today). Run diverse-lens
hunters and **union** their leads (recall ↑); then adversarially verify each (precision ↑),
since unioning raises the FP rate the proof lane must absorb.
- **Build:** the lens taxonomy + per-lens passes + completeness critic (landed this
  session) become a multi-agent fan-out at sweep time; verify panel refutes the union.
- **Free gate:** dedup/union math is deterministic and tested; no double-counting.
- **Billed gate:** found-rate ↑ **and** extra-confirmed (FP-proxy) **flat or down** vs
  Phase 1. Recall that costs precision is not a win.
- **Kill criterion:** if union recall gains are all absorbed by new FPs, the ensemble is
  noise — tune the lenses or drop it.

### Phase 6 — Precision & false-proof hardening *(the defender-value axis)*
Today 6/9 cases carry an extra-confirmed finding (FP-proxy). World-class is not just
finding more — it's a maintainer trusting the output. Strengthen the verify panel's
devil's-advocate gate, require execution proof (not reading) for memory verdicts (Lever 2,
landed), and grow the decoy corpus so precision is measured, not assumed.
- **Free gate:** false-proof rate = 0 on the bundled corpus (CI, already pinned).
- **Billed gate:** extra-confirmed ≤ 1/case on the CVE corpus.
- **Kill criterion:** any *false proof* on a decoy is a release blocker — the soundness
  contract is non-negotiable.

### Cross-cutting — the corpus is the real credibility lever
Every number above is only as honest as the corpus. **Grow it continuously** to ≥20 real
fix-derived CVE cases across memory/web/logic, fetch-on-demand (never committed), each with
a `vuln` and a guarded `safe` decoy. A claim of "world-class" on 9 cases is not credible;
on 20+ diverse held-out cases with both recall and precision pressure, it is.

## Sequencing & honest cost

Phases 0→1→(2,3,4 in parallel)→5→6. Phase 0 is the prerequisite (~$45). Phases 1–4 each
cost one CVE-corpus eval run (~$45–120) to validate; the free gates keep us from spending
on changes that don't survive a deterministic check first. Total to a defensible
world-class claim: a handful of billed eval runs (low hundreds of $) **plus** the corpus
expansion — not a model upgrade (the eval already showed Sonnet→Opus did not move the
find-rate; depth and methodology did).

## What this roadmap refuses to do
- Overfit the ranker/keyword list to the benchmark (documented false win).
- Claim a capability gain from a *free* change without a *billed* eval confirming it.
- Hide a tier as solved when it's the cloud-throughput lane's job. Some Tier-3 bugs may be
  permanently out of laptop-blind-static reach; the roadmap states that as a result, and
  routes them to execution (Phase 4) or names them out of scope — it does not paper over them.
