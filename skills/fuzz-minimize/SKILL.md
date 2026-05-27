---
name: fuzz-minimize
description: Record minimization status for triaged fuzz crashes. The MVP preserves crash groups and marks them not-minimized unless an engine-specific minimizer is later supplied.
allowed-tools: Bash
user-invocable: true
---

# Fuzz minimize

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-minimize.mjs" --target "<repo root>"`

Report how many crash groups were minimized. In the MVP, expect `not-minimized` unless a later
engine-specific minimizer has produced an input.
