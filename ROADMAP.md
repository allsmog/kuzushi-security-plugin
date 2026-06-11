# Roadmap

Tracked work for kuzushi-security-plugin. The plugin is a **local source-code**
review tool with static-first analysis and sandboxed proof (see
[Scope & boundaries](README.md#scope--boundaries)); roadmap items respect that
boundary unless explicitly noted.

## Toward world-class bug-finding

A push on the core capability — *finding real bugs* — landed across recall, precision,
proof, and measurement. Shipped:

- **Deep-by-default.** The CodeQL DB / Joern CPG now auto-build at session start when the
  engine CLI is present (local, no network), governed by `policy.analysis.autoBuildDatabases`
  (`scripts/lib/auto-build.mjs`). A **curated starter query pack** (`packs/starter/`,
  digest-attested via `install-starter-pack`) ships so the first interprocedural query needs
  no agent synthesis. This is the biggest recall lever — interprocedural taint no longer
  degrades to same-file linking by default.
- **Logic-bug track.** New `/logic-hunt` (logic-hunter agent) finds the bugs taint/SAST
  structurally miss — broken atomicity, ordering, state-machine skips, authorization-by-
  omission, replay, business-rule abuse — by adversarially violating intended-behavior
  invariants. Closed verdict gate in `logic-hunt-finalize`.
- **Differential PoC proof.** `/poc` now runs the verifier's `negativePoc` as a negative
  control: a harness that fires on benign input too is `non-discriminating`, not proof
  (`classifyDifferential`, proofLevel 5 for a discriminated proof).
- **Priority ranking.** Findings carry a deterministic `priority` (severity + proof state +
  attacker exposure + reach) so triage surfaces the unauth-reachable proven bug first
  (`scripts/lib/ranking.mjs`).
- **Coverage-guided fuzzing.** `/fuzz` parses engine coverage/telemetry (cov/ft, NEW/DONE,
  crash artifact) and emits per-engine minimizer commands (`scripts/lib/fuzz-telemetry.mjs`).
- **Benchmark harness.** `/benchmark` scores recall / precision / false-proof against a
  planted-vuln corpus (`bench/cases/`, `scripts/lib/bench-score.mjs`) so producer changes are
  provable; CI pins the corpus.
- **Intel feedback + propagation reach.** `/threat-intel` CVEs now boost taint CWE ranking;
  the flow-tracer propagates across async/event/queue boundaries; deserialization sources carry
  a gadget-chain caveat.

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

**Status:** Campaign planning, sandboxed execution, triage, **coverage-guided** run telemetry,
**per-engine crash minimization commands**, and promote-to-proven are consolidated under `/fuzz`
with `/fuzz-*` replay/debug stages. Remaining: automating the minimizer *execution* in-sandbox
(commands are surfaced today) and corpus-evolution feedback.

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
- Surface engine-native minimizer commands from the captured crash artifact; automating their
  in-sandbox execution is still pending.

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

These were approved but not yet built. They strengthen the static white-box mission:

- ~~**Sink→source (backward) tracing.**~~ **Done (v0.7.0).** `scripts/joern/taint-flows.sc` now
  has a `DIRECTION` token — `"backward"` runs `sources.reachableByFlows(sinks)` so a dangerous
  sink can be traced back to reachable sources; the flow-tracer sets it. Tree-sitter stays
  single-file/forward.
- ~~**Cross-finding chaining.**~~ **Done (v0.7.0).** `/chain` (chain-finder agent + chain-prepare/
  finalize) links related findings into higher-impact attack chains in `.kuzushi/chains.json` and
  attaches a `chains` ref onto each member (status unchanged).
- ~~**Per-finding remediation.**~~ **Done.** `scripts/lib/remediation.mjs` maps 33 CWE classes to
  concrete fixes (+ a generic floor); the `threat-hunt`, `systems-hunt`, and `taint-analysis`
  finalizers attach `remediation` to every actionable finding (agent's own wins, else the floor).
- ~~**Deeper routing introspection.**~~ **Done.** `scripts/lib/routes.mjs` adds web-framework route
  patterns (Express/Koa/Fastify/NestJS, Flask/Django, FastAPI, Spring, Go, Rails, ASP.NET) and an
  OpenAPI/Swagger spec parser (JSON + YAML) to the `/x-ray` entry-point sweep, so source enumeration
  catches web handlers and declared endpoints — feeding every downstream stage.
- **Engine-verified shipped queries.** The `codeql-verify` CI job compiles the starter pack against
  the CodeQL bundle; extend it to also verify Joern (needs a small fixture CPG) and to gate releases.
