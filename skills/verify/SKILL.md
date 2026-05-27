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
   (reconstruct source→sink → concrete trigger/payload **+ a negative PoC** → attempt every guard
   → **devil's-advocate** the opposite verdict → TRUE/FALSE-positive verdict + confidence + PoC
   sketch), using the `kuzushi-tree-sitter` taint tools
   (`tree_sitter:taint_sources` / `taint_sinks` / `callers` / `query`; codeql/joern only if a
   prebuilt DB/CPG already exists) and each candidate's matched threat-intel (`intel`).
3. Write the `{ candidates: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it validates the verdicts, persists `.kuzushi/verify.json`, and attaches
   a `verification` block onto each finding (tagging the PoC-ready ones).
4. Report the verdict counts, the `confirmed-exploitable` findings (fingerprint, CWE, the
   trigger), and which findings are now PoC-ready. Note the user can run `/poc` to empirically
   prove them.

## When NOT to use

- To *find* new bugs — verify only confirms findings a producer already wrote.
- Before any findings exist — run `/threat-hunt`, `/taint-analysis`, or `/systems-hunt` first.
- To empirically execute a PoC — that's `/poc`; verify is read-only and never runs code.

## Rationalizations to Reject

- *"The sink looks reachable, that's enough."* → `confirmed-exploitable` requires a **concrete
  trigger** (an actual payload + how it reaches the sink), not a plausibility argument.
- *"A guard is in the way, so not-exploitable."* → Name the guard **and** show every bypass you
  tried failed; an unbypassed-but-untested guard is `inconclusive`, not `not-exploitable`.
- *"I'm fairly sure, call it confirmed."* → Confidence is recorded explicitly; if you can't settle
  it from on-disk artifacts, the honest verdict is `inconclusive` with what runtime evidence is needed.
