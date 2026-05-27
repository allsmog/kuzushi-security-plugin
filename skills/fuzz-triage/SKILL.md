---
name: fuzz-triage
description: Group exploited fuzz-run results by deterministic crash hash and write .kuzushi/fuzz/fuzz-triage.json.
allowed-tools: Bash
user-invocable: true
---

# Fuzz triage

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-triage.mjs" --target "<repo root>"`

Report crash count and group count. Do not promote anything until `/fuzz-promote`.
