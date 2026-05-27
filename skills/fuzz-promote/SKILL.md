---
name: fuzz-promote
description: Attach fuzz evidence to findings and promote only exploited fuzz results to proven.
allowed-tools: Bash
user-invocable: true
---

# Fuzz promote

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-promote.mjs" --target "<repo root>"`

Report promoted fingerprints and the updated findings summary. This command only promotes fuzz
results with `proofVerdict:"exploited"`; everything else remains unproven.
