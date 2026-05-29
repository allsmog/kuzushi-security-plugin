---
name: deep-context
description: Deep system-understanding pass before threat modeling. The context-analyst agent reads the code (line-by-line where it matters) and builds a grounded model — modules, entry points, actors, trust boundaries, data stores, system invariants — with file:line evidence, written to .kuzushi/deep-context.json. Context only — it never finds vulns, fixes, or severities. Best run after x-ray, before /threat-model.
context: fork
agent: context-analyst
user-invocable: false
---

# Deep context

Build a grounded understanding of the system before hunting bugs (shallow context is where missed
bugs and false positives come from).

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/deep-context-prepare.mjs" --target "<repo root>"`.
   Read the prep's `prepPath` (inventory + x-ray entry points as leads).
2. Work the three phases — orientation (modules / entry points / actors / data stores) →
   ultra-granular analysis of the security-relevant components (read line-by-line, trace
   cross-function flows, record the **invariants** the code assumes) → a global data-flow + trust
   model — grounding every claim in a file you read (`tree_sitter:*`, LSP, Grep). Record anything
   suspicious as an **open question**, never a finding.
3. Write the `{ systemOverview, modules, entryPoints, actors, trustBoundaries, dataStores,
   invariants, openQuestions }` bundle to the prep's `draftPath`, then run the `assembleCommand`
   — it enforces the context-only boundary and persists `.kuzushi/deep-context.json`.
4. Report the overview, the counts, the key invariants, and the open questions. `/threat-model`
   will build on it.

## When NOT to use

- When a quick inventory is enough — that's the SessionStart context / `/threat-model`'s own scope;
  this is the slower, deeper reasoning pass.
- To find or fix bugs — strictly out of scope here; use `/threat-hunt`, `/taint-analysis`,
  `/systems-hunt`, and `/verify`.

## Rationalizations to Reject

- *"The framework implies the design."* → Read the code; assumed designs miss real trust boundaries.
- *"That looks like a bug — flag it."* → Record an `openQuestion`; the hunts adjudicate, not this stage.
- *"Skip the confusing module."* → That's often where bugs hide; if you can't resolve it, say so in
  `openQuestions` rather than glossing over it.
