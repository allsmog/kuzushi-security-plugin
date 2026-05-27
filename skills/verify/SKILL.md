---
name: verify
description: Exploitability verification of the findings index. For each open / trace-needed finding in .kuzushi/findings.json, reconstruct source→sink, build a concrete trigger, and assign a proof verdict (confirmed-exploitable / not-exploitable / inconclusive) with a PoC sketch. Read-only — attaches a verification block onto each finding and tags the PoC-ready ones for /poc. Requires /threat-hunt (or /taint-analysis) first.
context: fork
agent: verifier
user-invocable: true
---

# Verify

Verify the exploitability of the open findings for the current repository.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/verify-prepare.mjs" --target "<repo root>"`.
   If it reports no findings index, tell the user to run `/threat-hunt` (or `/taint-analysis`)
   first and stop.
2. Read the prep's `prepPath`. For **each** candidate finding, do the full verify walk
   (reconstruct source→sink → construct a concrete trigger/payload → attempt every guard →
   verdict + confidence + PoC sketch), using the `kuzushi-tree-sitter` taint tools
   (`tree_sitter:taint_sources` / `taint_sinks` / `callers` / `query`; codeql/joern only if a
   prebuilt DB/CPG already exists) and each candidate's matched threat-intel (`intel`).
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates the verdicts, persists `.kuzushi/verify.json`, and attaches
   a `verification` block onto each finding (tagging the PoC-ready ones).
4. Report the verdict counts, the `confirmed-exploitable` findings (fingerprint, CWE, the
   trigger), and which findings are now PoC-ready. Note the user can run `/poc` to empirically
   prove them.
