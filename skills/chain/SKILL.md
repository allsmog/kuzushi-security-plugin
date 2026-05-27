---
name: chain
description: Link related findings into higher-impact attack chains. The chain-finder agent reasons over the findings index for compositions (precondition → pivot → impact) — e.g. an auth bypass that turns a read-only SSRF into internal RCE — and records each chain with an ordered narrative + member fingerprints in .kuzushi/chains.json, attaching a `chains` ref onto each member finding (status unchanged). Needs ≥2 live findings.
context: fork
agent: chain-finder
user-invocable: true
---

# Cross-finding chaining

Findings are triaged independently; this connects them into **attack chains** where one finding
escalates another's impact. Requires ≥2 live findings in `.kuzushi/findings.json` (run the hunts
first).

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/chain-prepare.mjs" --target "<repo root>"`. If
   there are fewer than 2 live findings, tell the user to run more hunts and stop. Read `prepPath`.
2. Identify genuine compositions (precondition → pivot → impact), ordering members and naming the
   data/control link between steps. Use each finding's `fingerprint` verbatim as a member id.
   Write the `{ chains: [...] }` bundle to the prep's `draftPath`. If nothing genuinely composes,
   write `{ "chains": [] }` — don't force a chain.
3. Run the `assembleCommand` (finalize). It validates each chain (≥2 real members, ordered
   narrative), writes `.kuzushi/chains.json`, and attaches a `chains` ref onto each member finding
   (status unchanged). Report the chains highest-escalated-impact first.
