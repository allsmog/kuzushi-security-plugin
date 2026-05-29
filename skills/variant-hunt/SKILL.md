---
name: variant-hunt
description: Variant analysis — find siblings of a confirmed bug. For each confirmed/exploitable finding in .kuzushi/findings.json, the variant-hunter agent sweeps the repo for other sites with the same bug class (exact match → generalize), triages each, and promotes variants into findings.json (source "variant-hunt", refId variant-of:<seed>). Requires at least one confirmed finding first.
context: fork
agent: variant-hunter
user-invocable: false
---

# Variant hunt

Find other instances of the bugs already confirmed for this repository.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/variant-hunt-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxSeeds":8}'`). If it reports `no-seeds`, tell the user to confirm a
   finding first (`/threat-hunt` → `/verify`, or `/systems-hunt` / `/taint-analysis`) and stop.
2. Read the prep's `prepPath`. For **each** seed, do the narrow→general walk (understand the
   root cause → exact match → identify abstraction points → generalize one step at a time →
   triage each hit) using `runRg`/Grep, then `semgrep:scan`, then `codeql:query`/`joern:query`
   if a DB/CPG exists. Use each `seedFingerprint` verbatim.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` (finalize) — it validates verdicts and promotes variants into
   `.kuzushi/findings.json` (`source:"variant-hunt"`, `refId:"variant-of:<seed>"`).
4. Report, per seed, the variants found and their verdicts, and list the new `exploitable` sites
   (file:line + why it's the same bug).

## When NOT to use

- Before any finding is confirmed — there's nothing to find variants of.
- As the initial bug hunt — use `/threat-hunt`, `/taint-analysis`, or `/systems-hunt` first; this
  replicates a *known* bug, it doesn't discover the first one.

## Rationalizations to Reject

- *"Same API call ⇒ same bug."* → A guard the seed lacked may be present at this site; confirm
  before calling it `exploitable` (else `reviewed-no-impact`, naming the guard).
- *"Cast the widest net to be thorough."* → Generalize one abstraction point at a time; over-broad
  patterns bury real variants in noise.
- *"A grep hit is a variant."* → It's a lead; open it and confirm reachability + the missing guard
  like the original hunt did.
