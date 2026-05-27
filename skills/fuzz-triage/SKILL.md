---
name: fuzz-triage
description: Low-level stage for /fuzz. Group exploited fuzz-run results by deterministic crash hash. Prefer /fuzz --stage replay for normal use.
allowed-tools: Bash
user-invocable: true
---

# Fuzz triage

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-triage.mjs" --target "<repo root>"`

Report crash count and group count. Do not promote anything until `/fuzz-promote`.
