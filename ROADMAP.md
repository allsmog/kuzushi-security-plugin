# Roadmap

Tracked work for kuzushi-security-plugin. The plugin is a **local source-code**
review tool with static-first analysis and sandboxed proof (see
[Scope & boundaries](README.md#scope--boundaries)); roadmap items respect that
boundary unless explicitly noted.

## Future direction

### Fuzzing campaign harness (dynamic complement for native targets)

**Status:** MVP command surface landed — campaign planning, sandboxed execution,
triage, minimization ledger, and promote-to-proven are available as `/fuzz-*`.
Deeper engine-specific harness synthesis and minimizers remain follow-up work.

For libraries / native / parser / CLI targets there's no HTTP layer to proxy, so the dynamic
complement to static review is **fuzzing**, not a web proxy. `/poc` builds a *single*
harness that fires one reconstructed payload. `/fuzz-init` through `/fuzz-promote` now provide
the campaign artifact path:

- Generate or review a libFuzzer/Jazzer/Node/Go/Rust harness in `.kuzushi/fuzz/harnesses/`.
- Run a time-boxed, offline campaign with sanitizer/crash classification.
- Triage crashes back to findings, attach a `fuzz` block, and promote only empirical crashes.
- Preserve minimization status; engine-native minimizer automation is still pending.

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
