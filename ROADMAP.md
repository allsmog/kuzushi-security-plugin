# Roadmap

Tracked work for kuzushi-security-plugin. The plugin is a **white-box, static source-code**
review tool (see [Scope & boundaries](README.md#scope--boundaries)); roadmap items respect
that boundary unless explicitly noted.

## Future direction

### Fuzzing campaign harness (dynamic complement for native targets)

**Status:** TODO — larger effort, not yet scoped into a skill.

For libraries / native / parser / CLI targets there's no HTTP layer to proxy, so the dynamic
complement to static review is **fuzzing**, not a web proxy. Today `/poc` builds a *single*
ASAN/crash harness that fires one reconstructed payload. The next step is a coverage-guided
**fuzzing campaign**:

- Generate a libFuzzer / AFL++ harness (not just a one-shot driver) targeting the suspect
  function or parser entry point.
- Build with sanitizers (ASan/UBSan/MSan) and run a time-boxed, coverage-guided campaign with
  a seed corpus.
- Triage crashes back to findings (dedupe by stack hash), attach a `fuzz` block to the matching
  finding alongside the existing `poc` block.
- Keep it sandboxed and offline, consistent with `/poc` (`--network none`).

This is the natural extension of `/poc` for memory-safety / parser bugs and pairs with
`/systems-hunt` + `/mem-exploitability`. It is a meaningful new capability, not a bug fix.

## Planned (in-scope static fixes)

These were approved but not yet built. They strengthen the static white-box mission:

- **Sink→source (backward) tracing.** Forward source→sink is strong (Joern
  `sinks.reachableByFlows(sources)` in `scripts/joern/taint-flows.sc`); add the reverse
  (`sources.reachableByFlows(sinks)`) so a dangerous sink can be traced back to reachable
  sources. Tree-sitter is single-file only — backward cross-file needs the Joern/CodeQL path.
- **Cross-finding chaining.** `findings.json` has no relationships today (`chain-finder` is
  referenced in `scripts/lib/findings.mjs` but unimplemented). Add a stage that links related
  findings (e.g. authz-bypass + SSRF) into higher-impact chains via stable fingerprints.
- **Per-finding remediation.** Only `/mem-exploitability` attaches `remediation` today
  (`scripts/cmd/mem-exploitability-finalize.mjs`). Extend `threat-hunt`, `systems-hunt`, and
  `taint-analysis` finalizers to carry concrete fix guidance per finding.
- **Deeper routing introspection.** Entry-point detection is 7 hardcoded regex patterns in
  `scripts/cmd/x-ray.mjs` (`ENTRY_POINT_PATTERNS`). Add framework route-table / OpenAPI parsing
  (Express, Django, FastAPI, Spring) so source enumeration misses fewer handlers — this feeds
  every downstream stage.
