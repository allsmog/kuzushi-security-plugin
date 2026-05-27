---
name: fuzz
description: Canonical fuzzing workflow for confirmed/proven findings. Coordinates plan → author harnesses (fuzz-harness-author agent) → replay → triage → promote, and advances a finding to proven only on empirical crash/sanitizer evidence. Prefer this over the lower-level /fuzz-* stage commands.
user-invocable: true
---

# Fuzz workflow

Use `/fuzz` as the main workflow — you are the **coordinator**: run the deterministic stages and
spawn the harness-authoring subagent between them. The lower-level `/fuzz-init`, `/fuzz-run`,
`/fuzz-triage`, `/fuzz-minimize`, and `/fuzz-promote` commands are replay/debug stages behind this
surface.

1. Run:
   `node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz.mjs" --target "<repo root>" --stage plan`
   If it returns `no-seeds`, tell the user to run `/verify` first and stop.
2. Spawn the **`fuzz-harness-author`** agent with the Task tool, passing it the target directory and
   the `.kuzushi/fuzz/fuzz-plan.json` path. It writes a real harness into each candidate's
   `harnessDir`, seeds the corpus, sets a concrete offline `runCommand` + `expectedSignal` (using the
   recommended engine + `semanticOracle` controls), and writes the updated plan back in place. Wait
   for it to finish.
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
