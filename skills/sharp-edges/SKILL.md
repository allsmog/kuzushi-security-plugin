---
name: sharp-edges
description: Find footgun APIs, dangerous defaults, and misuse-prone designs (where the secure path isn't the default). The sharp-edges-analyzer agent reasons through three adversaries (scoundrel / lazy dev / confused dev) across six categories and promotes real edges into .kuzushi/findings.json (source "sharp-edges"). Distinct from /sast (injection) and the insecure-defaults companion (config values).
context: fork
agent: sharp-edges-analyzer
user-invocable: false
---

# Sharp edges

Find the APIs and configs where it's *easy to be insecure* — secure usage should be the path of
least resistance.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/sharp-edges-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxCandidates":30}'`). If it reports `no-candidates`, say so and stop.
   Read the prep's `prepPath`.
2. For **each** candidate, open the site and reason through the three adversaries (scoundrel /
   lazy dev / confused dev) across the six categories (algorithm-selection, dangerous-defaults,
   primitive-vs-semantic, configuration-cliff, silent-failures, stringly-typed-security). Decide
   `finding` / `candidate` / `rejected`.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates verdicts/categories and promotes them into
   `.kuzushi/findings.json` (`source:"sharp-edges"`).
4. Report findings by category (file:line, the adversary, the safer-by-default API to prefer).

## When NOT to use

- For injection / source→sink bugs — that's `/sast` and `/taint-analysis`.
- For hardcoded secrets / config *values* — that's the `insecure-defaults` companion; here the
  concern is the API/config *shape* that invites misuse.

## Rationalizations to Reject

- *"Used correctly here, so fine."* → The edge is that it's easy to use *wrong*; insecure-by-default
  is still a finding even if this call site is OK.
- *"It's just a default."* → The scoundrel/lazy dev won't fix it; insecure-by-default is the bug.
- *"Scary but unprovable."* → That's `candidate`, not `finding` — and not silently dropped.
