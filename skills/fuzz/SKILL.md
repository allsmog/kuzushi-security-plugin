---
name: fuzz
description: Canonical fuzzing workflow for confirmed/proven findings. Plans campaign harnesses, runs declared fuzz harnesses offline, triages crashes, records minimization state, and promotes only empirical crash/sanitizer evidence to proven. Prefer this over the lower-level /fuzz-* stage commands.
context: fork
agent: fuzz-harness-author
allowed-tools: Bash, Read, Write, Edit
user-invocable: true
---

# Fuzz workflow

Use `/fuzz` as the main workflow. The lower-level `/fuzz-init`, `/fuzz-run`,
`/fuzz-triage`, `/fuzz-minimize`, and `/fuzz-promote` commands are replay/debug
stages behind this surface.

1. Run:
   `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz.mjs" --target "<repo root>" --stage plan`
   If it returns `no-seeds`, tell the user to run `/verify` first and stop.
2. Read `.kuzushi/fuzz/fuzz-plan.json`. For each candidate, write or refine the
   harness only inside its `harnessDir`, using the recommended engine and
   `semanticOracle` controls as guidance. Keep `runCommand` concrete and offline.
   The `fuzz-harness-author` agent owns this harness-writing step.
3. Run:
   `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz.mjs" --target "<repo root>" --stage replay`
   Add `--trust-local` only if Docker is unavailable and the user explicitly
   accepts local execution.
4. Report replay results: run verdict counts, crash group count, minimization
   status, promoted fingerprints, and updated findings summary.

## When NOT to use

- Before a finding is confirmed/proven.
- As a live web-app DAST replacement.
- To claim a bug from a fuzzer timeout or build failure; only
  `proofVerdict:"exploited"` promotes.
