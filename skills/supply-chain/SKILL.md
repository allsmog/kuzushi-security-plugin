---
name: supply-chain
description: Audit direct dependencies for takeover / abandonment risk (maintainer count, popularity, CVE history, release cadence, ownership) and promote the risky ones into .kuzushi/findings.json (source "supply-chain"). Complements /threat-intel (which checks CVEs, not dependency trustworthiness). Uses the network — asks first.
context: fork
agent: supply-chain-auditor
user-invocable: true
---

# Supply-chain risk audit

Assess whether this project's direct dependencies are trustworthy to depend on.

1. Run `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/supply-chain-prepare.mjs" --target "<repo root>"`
   (optionally `--input '{"maxDeps":40}'`). If it reports `no-deps`, tell the user no manifests
   were found and stop. Read the prep's `prepPath`.
2. **This step uses the network** (registry + repo metadata) — confirm with the user first. For
   each notable dependency, gather metadata (`gh` + WebSearch/WebFetch): maintainer count,
   popularity, release recency, CVE/advisory history, ownership transfers. Assign a `riskTier`
   (high/medium/low) with the factors.
3. Write the `{ dependencies: [...] }` bundle to the prep's `draftPath`, then run the
   `assembleCommand` — it persists `.kuzushi/supply-chain.json` and promotes high→finding,
   medium→candidate into `.kuzushi/findings.json` (`source:"supply-chain"`).
4. Report the tier breakdown and the high-risk deps (name, deciding factor, the fix).

## When NOT to use

- To find known CVEs in dependencies — that's `/threat-intel`; this is takeover/abandonment risk.
- Offline — it needs registry/repo metadata.
- To scan first-party source — use `/threat-hunt`, `/taint-analysis`, `/sast`.

## Rationalizations to Reject

- *"Popular ⇒ safe."* → A popular single-maintainer package with stale releases is a prime takeover
  target; weigh maintainers + cadence, not stars.
- *"No CVE ⇒ no risk."* → Takeover/abandonment risk is forward-looking; past-CVE absence is irrelevant.
- *"List every transitive dep."* → Stay on direct deps you control; note transitive concerns as
  nextChecks rather than flooding findings.
