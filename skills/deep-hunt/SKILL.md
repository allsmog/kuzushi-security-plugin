---
name: deep-hunt
description: Interprocedural, hypothesis-driven hunt — finds the multi-file source→sink bugs that pattern-gating and same-file taint miss. Ranks trace anchors (entry points + dangerous sinks), then the deep-hunter agent walks each flow ACROSS files (forward/backward call-graph CLIs) over multiple rounds, confirming propagation and defeating guards, and promotes confirmed cross-file flows into findings.json with the path stored as evidenceGraph. Token-expensive, budget-bounded. Part of the HUNT phase (run via /sweep --deep, or ask for it); leads flow to /verify (panel).
context: command
runner: scripts/cmd/deep-hunt-run.mjs
user-invocable: false
---

# Deep hunt (interprocedural hypothesis loop)

The recall lever beyond `/deep-scan` (which reads whole files) and `/taint-analysis` (which
traces labeled source→sink, sound only with a CPG): walk a flow **across files** by forming a
hypothesis at an anchor and following the data hop by hop. This is how the multi-file bugs —
input in one file, sink in a third — get caught without a 2 GB CPG.

1. Prefer the provider-neutral command:
   `KUZUSHI_MODEL="${KUZUSHI_MODEL:-openai-codex:gpt-5.5}" node "<plugin root>/scripts/cmd/deep-hunt-run.mjs" --target "<repo root>"`.
   Add `--input '{"scopeDir":"<dir>","maxAnchors":24}'` to scope/bound it. The runner performs
   prepare -> configured LLM bridge -> finalize without depending on a Claude subagent runtime.
2. Manual fallback only when the runner is unavailable: run
   `node "<plugin root>/scripts/cmd/deep-hunt-prepare.mjs" --target "<repo root>"`, read
   `prepPath`, walk each anchor with the listed `callees`/`callers` CLIs, write
   `{ candidates: [...] }` to `draftPath`, then run the returned `assembleCommand`.
3. The
   finalizer enforces that a `finding` carries a **confirmed cross-file path** (≥2 hops, ≥2
   files), stores it as the finding's `evidenceGraph`, and promotes under source `deep-hunt`.
   Report the flows found + evidence levels, and note they should go through `/verify` (panel).

## When NOT to use

- On a single-file script or pure config/binary target — use `/deep-scan`, `/iac`, or
  `/binary-recon`. Deep-hunt earns its token cost only when flows cross files.
- To confirm/prove an existing finding — that's `/verify` → `/poc` / `/sanitize-pov`. Deep-hunt
  *discovers* new interprocedural flows.
- Before there's any entry surface to start from — build context (`/threat-model`, `/code-graph`)
  first so the anchors and reachability are populated.

## Rationalizations to Reject

- *"A call to the sink exists, so it's a finding."* → A call site is not propagation. Confirm the
  tainted value reaches the sink and that no guard stops it, or it's a `candidate`.
- *"No CPG, so I can't trace across files."* → Walk the call graph with `callees`/`callers` and
  read each hop; a confirmed cross-file chain is honest `linked` evidence. Same-file-only is the
  exact miss this skill fixes.
- *"Too many anchors — I'll just check a few and call it done."* → Spend the budget, then **report
  the unreached anchors + `unanchoredCount`**. Silent truncation reads as "covered everything."
- *"It's three files deep, skip it."* → That depth is the target; the shallow ones the other
  producers already found.
