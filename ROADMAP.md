# Roadmap

Tracked work for kuzushi-security-plugin. The plugin is a **local source-code**
review tool with static-first analysis and sandboxed proof (see
[Scope & boundaries](README.md#scope--boundaries)); roadmap items respect that
boundary unless explicitly noted.

## Raising detection power (current priority)

The mission: find **more** bugs, **harder** bugs, and **chain** them into real attack
paths. Recall and difficulty are gated by structural ceilings in today's pipeline — not
by model quality (the eval showed model tier is *not* the find-rate lever; depth and
reachability are). Each lever below removes one ceiling, ordered by leverage.

**Shipped so far:** the forward call-graph primitive (`crossFileCallees` + `callees.mjs`
— the missing half of interprocedural walking); **L1** (the taint flow-tracer now walks
across files without a CPG); **L2** (`/deep-hunt`, the hypothesis loop); **L3** (`/chain`
upgraded to a proactive attack-path search); **L4** (framework-aware route enumeration —
`routes.mjs` + `routes.mjs` CLI, feeding `/deep-hunt` anchors and the risk ranker).
Runtime recall of these still needs the LLM-in-the-loop eval lane exercised — the
*capability* is in, the *measurement* is next. L5–L6 are the remaining levers.

### L1 — Interprocedural dataflow by default
Cross-function source→sink only runs when a Joern CPG / CodeQL DB exists
(`scripts/joern/taint-flows.sc`, forward + backward). Without one, taint degrades to
**same-file** linking and `callers.mjs` is a **single-hop textual hint** ("not sound
dataflow"). Multi-file flows are exactly the hard bugs, so they're structurally
under-covered. Plan: auto-build / strongly nudge the CPG for `/sweep --deep` and
`/verify`, route flow through it, and give the agent a **multi-hop `callers.mjs` walk**
to trace a flow across files when no CPG is present. The #1 "more + harder" lever.

### L2 — Hypothesis-driven deep-hunt loop
Producers are one-pass (read → emit). Add an iterative investigation mode: rank a
sink / entry point → form a hypothesis → pull in callees / callers / related functions →
confirm or refute over N rounds with full-function context → emit candidate flows. This
is how a human auditor (and a cloud agent swarm) finds the non-obvious, reasoning-heavy
bugs. Builds on `/deep-scan`, `callers.mjs`, and the `/verify` panel.

### L3 — Proactive attack-path engine — *in progress*
`/chain` today only **composes findings that already exist** (`chain-prepare.mjs`).
Upgrade it to **search** entry→asset paths over the threat-model assets + the code-graph
reachability graph, composing even **sub-threshold** primitives (candidate / lead) into a
critical chain — the "two mediums + a low ⇒ RCE" compositions cloud tools are praised for.
Feeds the `/report` "Attack chains" section.

### L4 — Framework-aware entry-point enumeration — ✅ shipped
Entry points are hand-written regexes (`risk-rank.mjs` `ENTRY_DEF`, x-ray
`ENTRY_POINT_PATTERNS`), so framework route tables / OpenAPI specs are missed and their
handlers never get read — uncovered surface is uncovered bugs. Parse Express / Django /
FastAPI / Spring routers + OpenAPI so every handler becomes attacker-reachable surface
the readers cover. (Supersedes the older "deeper routing introspection" item.)

### L5 — Ensemble discovery + closed feedback loop
Diversity exists only at verification (the panel), not discovery. Run diverse-lens
hunters and **union** their leads (recall), then adversarially verify (precision). Close
the loop: feed verify's "couldn't reach the sink" back into routing, and `/poc`'s
"proven" into `/variant-hunt`.

*Partial:* `/sweep --partition` adds a deterministic attack-surface overlay (subsystem
jobs on top of the dir-shards) so hunters diverge across attack paths at discovery time;
semantic dedup (`enclosingFnKey`) unions the duplicates in the findings index. The
closed feedback loop (verify→routing, proven→variant) is still open.

### L6 — Class-specialized deep reasoning
Some classes need methodology, not patterns: deserialization / prototype-pollution
**gadget chains**, **TOCTOU / races**, integer-overflow → OOB, type confusion. Dedicated
deep agents per class find instances the generic readers miss.

## Dynamic proof — fuzzing campaign harness (native targets)

**Status:** MVP command surface landed — campaign planning, sandboxed execution,
triage, minimization ledger, and promote-to-proven are consolidated under `/fuzz`
with `/fuzz-*` replay/debug stages. Deeper engine-specific harness synthesis and
minimizers remain follow-up work.

**Discovery by execution landed (`/fuzz --stage discover`, `/sweep` `fuzz-discover`
producer):** the routing-independent lane that finds memory bugs by *running* crafted
inputs under sanitizers with no pre-existing finding — recon-prepare → fuzz-discoverer
agent → fuzz-discover-finalize (the sanitizer report promotes a NEW `proven` finding).
The promotion spine is unit- + end-to-end-tested; the **blind 9-CVE find-rate gate**
(`npm run eval:discover:cve`, ≥3/6 memory cases) is the merge bar and has not yet been
run (it needs an environment that permits headless discovery agents).

For libraries / native / parser / CLI targets there's no HTTP layer to proxy, so the
dynamic complement to static review is **fuzzing**, not a web proxy. `/poc` builds a
*single* harness that fires one reconstructed payload; `/fuzz` provides the campaign path:

- Generate or review a libFuzzer / Jazzer / Node / Go / Rust harness in `.kuzushi/fuzz/harnesses/`.
- Run a time-boxed, offline campaign with sanitizer / crash classification.
- Triage crashes back to findings, attach a `fuzz` block, and promote only empirical crashes.
- Preserve minimization status; engine-native minimizer automation is still pending.

Pairs with `/systems-hunt` + `/mem-exploitability` and feeds L6 (memory-class reasoning).

## Done

- ~~**Sink→source (backward) tracing.**~~ **v0.7.0.** `scripts/joern/taint-flows.sc` has a
  `DIRECTION` token — `"backward"` runs `sources.reachableByFlows(sinks)` so a dangerous sink
  traces back to reachable sources; the flow-tracer sets it. (L1 builds on this.)
- ~~**Cross-finding chaining (post-hoc).**~~ **v0.7.0.** `/chain` links existing findings into
  attack chains. **L3 above is the next step: proactive path *search*, not just composition.**
- ~~**Prioritized human report.**~~ `/report` ranks findings fix-first and renders chains /
  coverage / provenance (`scripts/lib/risk.mjs`).

## Planned (in-scope static fixes)

- **Per-finding remediation.** Only `/mem-exploitability` attaches `remediation` today
  (`scripts/cmd/mem-exploitability-finalize.mjs`). Extend `threat-hunt`, `systems-hunt`, and
  `taint-analysis` finalizers to carry concrete fix guidance per finding — which also enriches
  the `/report` and the L3 chain narratives.
