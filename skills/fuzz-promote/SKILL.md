---
name: fuzz-promote
description: Low-level stage for /fuzz. Attach fuzz evidence to findings and promote only exploited fuzz results to proven. Prefer /fuzz --stage replay for normal use.
allowed-tools: Bash
user-invocable: false
---

# Fuzz promote

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-promote.mjs" --target "<repo root>"`

Report promoted fingerprints and the updated findings summary. This command only promotes fuzz
results with `proofVerdict:"exploited"`; everything else remains unproven.
