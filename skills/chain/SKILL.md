---
name: chain
description: Proactive attack-path engine. The chain-finder agent SEARCHES for ordered entry→…→asset attack paths where each step is enabled by a finding — composing even sub-threshold (candidate/lead) primitives into a critical chain — using the threat-model assets, attacker-reachable entry points, and the reachability graph. Records each path (ordered narrative + member fingerprints) in .kuzushi/chains.json and attaches a `chains` ref onto each member (status unchanged). Needs ≥2 live findings.
context: fork
agent: chain-finder
user-invocable: false
---

# Attack-path chaining

Findings are triaged independently; the highest-impact issues are often a *path* assembled from
individually-unremarkable bugs (a low info-leak + a medium auth gap + a candidate SSRF ⇒ critical
RCE). This **searches** for those paths — it doesn't just restate confirmed findings. Requires ≥2
live findings in `.kuzushi/findings.json` (run the hunts first); richer with a threat model +
code-graph built (they supply the assets + reachability the search keys off).

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/chain-prepare.mjs" --target "<repo root>"`. If
   there are fewer than 2 live findings, tell the user to run more hunts and stop. Read `prepPath` —
   it carries the findings (incl. sub-threshold leads), the crown-jewel `context.assets`, the
   attacker-reachable `context.entryPoints`, and a `context.reachability` summary.
2. Search **entry→asset** paths (forward from entry points, backward from assets, meet in the
   middle) where each step is enabled by a finding; compose sub-threshold primitives where the
   composition is what makes it critical. Order members, name the data/control link between steps,
   and use each `fingerprint` verbatim. Write `{ chains: [...] }` (with `kind`/`entryPoint`/`asset`)
   to `draftPath`. If nothing genuinely composes, write `{ "chains": [] }` — don't force a chain.
3. Run the `assembleCommand` (finalize). It validates each chain (≥2 real members, ordered
   narrative ≥120 chars), **escalates** severity to at least the max member's (composed impact is
   never under-reported), writes `.kuzushi/chains.json`, and attaches a `chains` ref onto each
   member (status unchanged). Report the paths highest-impact first; `/report` renders them.

## When NOT to use

- Before ≥2 live findings exist — run `/sweep` / `/threat-hunt` / `/taint-analysis` first.
- To discover new bugs — chaining only connects existing findings; name missing links as gaps.

## Rationalizations to Reject

- *"All low/candidate — not worth chaining."* → Composing sub-threshold primitives into a critical
  is the whole point; severity-gating the links misses the chains that matter most.
- *"Same bug class, so they chain."* → A link needs one finding's effect to satisfy the next's
  precondition — name that edge or drop it. Co-occurrence ≠ composition.
