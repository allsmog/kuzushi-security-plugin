---
name: fuzz-run
description: Execute runnable fuzz harnesses from .kuzushi/fuzz/fuzz-plan.json in an offline sandbox, recording empirical crash/sanitizer evidence to .kuzushi/fuzz/fuzz-run.json.
allowed-tools: Bash
user-invocable: true
---

# Fuzz run

Run:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-run.mjs" --target "<repo root>"`

If Docker is unavailable and the user explicitly accepts local execution, rerun with `--trust-local`.
Report the verdict counts. Only `proofVerdict:"exploited"` is empirical fuzz proof.
