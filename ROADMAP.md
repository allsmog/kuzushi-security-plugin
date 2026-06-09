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

### Fuzzing campaign harness (dynamic complement for native targets)

**Status:** Campaign planning, sandboxed execution, triage, **coverage-guided** run telemetry,
**per-engine crash minimization commands**, and promote-to-proven are consolidated under `/fuzz`
with `/fuzz-*` replay/debug stages. Remaining: automating the minimizer *execution* in-sandbox
(commands are surfaced today) and corpus-evolution feedback.

For libraries / native / parser / CLI targets there's no HTTP layer to proxy, so the dynamic
complement to static review is **fuzzing**, not a web proxy. `/poc` builds a *single*
harness that fires one reconstructed payload. `/fuzz` now provides the campaign artifact path:

- Generate or review a libFuzzer/Jazzer/Node/Go/Rust harness in `.kuzushi/fuzz/harnesses/`.
- Run a time-boxed, offline campaign with sanitizer/crash classification.
- Triage crashes back to findings, attach a `fuzz` block, and promote only empirical crashes.
- Surface engine-native minimizer commands from the captured crash artifact; automating their
  in-sandbox execution is still pending.

This is the natural extension of `/poc` for memory-safety / parser bugs and pairs with
`/systems-hunt` + `/mem-exploitability`. It is a meaningful new capability, not a bug fix.

## Planned (in-scope static fixes)

These were approved but not yet built. They strengthen the static white-box mission:

- ~~**Sink→source (backward) tracing.**~~ **Done (v0.7.0).** `scripts/joern/taint-flows.sc` now
  has a `DIRECTION` token — `"backward"` runs `sources.reachableByFlows(sinks)` so a dangerous
  sink can be traced back to reachable sources; the flow-tracer sets it. Tree-sitter stays
  single-file/forward.
- ~~**Cross-finding chaining.**~~ **Done (v0.7.0).** `/chain` (chain-finder agent + chain-prepare/
  finalize) links related findings into higher-impact attack chains in `.kuzushi/chains.json` and
  attaches a `chains` ref onto each member (status unchanged).
- **Per-finding remediation.** Only `/mem-exploitability` attaches `remediation` today
  (`scripts/cmd/mem-exploitability-finalize.mjs`). Extend `threat-hunt`, `systems-hunt`, and
  `taint-analysis` finalizers to carry concrete fix guidance per finding.
- **Deeper routing introspection.** Entry-point detection is 7 hardcoded regex patterns in
  `scripts/cmd/x-ray.mjs` (`ENTRY_POINT_PATTERNS`). Add framework route-table / OpenAPI parsing
  (Express, Django, FastAPI, Spring) so source enumeration misses fewer handlers — this feeds
  every downstream stage.
