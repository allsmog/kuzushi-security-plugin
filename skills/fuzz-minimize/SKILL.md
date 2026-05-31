---
name: fuzz-minimize
description: Low-level stage for /fuzz. Record minimization status for triaged fuzz crashes. Prefer /fuzz --stage replay for normal use.
allowed-tools: Bash
user-invocable: false
---

# Fuzz minimize

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-minimize.mjs" --target "<repo root>"`

Report how many crash groups were minimized. In the MVP, expect `not-minimized` unless a later
engine-specific minimizer has produced an input.
