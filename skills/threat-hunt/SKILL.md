---
name: threat-hunt
description: Adversarial per-threat review (Carlini doctrine). For each threat in .kuzushi/threat-model.json, state attacker capabilities, walk source→sink, attempt to bypass every guard, and assign a verdict with evidence. Promotes findings into .kuzushi/findings.json. Requires /threat-model first.
context: fork
agent: threat-hunter
user-invocable: true
---

# Threat hunt

Run the adversarial per-threat review for the current repository.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/threat-hunt-prepare.mjs" --target "<repo root>"`.
   If it reports no threat model, tell the user to run `/threat-model` first and stop.
2. Read the prep's `prepPath`. For **each** candidate threat, do the full 6-step walk
   (attacker capabilities → source/sink → enumerate guards → bypass every guard → verdict →
   next-checks), using the tree-sitter taint tools (`tree_sitter:taint_sources` / `taint_sinks`
   / `callers` / `query`; codeql/joern only if a DB/CPG exists) and the matched threat-intel
   bypass knowledge in each candidate's `intel`.
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` (finalize) — it validates the verdicts and promotes them into
   `.kuzushi/findings.json`.
4. Report the verdict counts and the `exploitable` findings (threatId, CWE, source→sink +
   the bypass), and note that `.kuzushi/findings.json` holds the open findings.
