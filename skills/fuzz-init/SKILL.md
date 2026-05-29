---
name: fuzz-init
description: Low-level stage for /fuzz. Initialize a local fuzzing campaign plan from confirmed/proven findings. Prefer /fuzz for normal use.
allowed-tools: Bash, Read, Write, Edit
user-invocable: false
---

# Fuzz init

Create the campaign plan and harness workspaces:

`node "${CLAUDE_PLUGIN_ROOT}/scripts/cmd/fuzz-init.mjs" --target "<repo root>"`

If it returns `no-seeds`, tell the user to run `/verify` first. If it returns `prepared`, read
`.kuzushi/fuzz/fuzz-plan.json`, write or refine the harness files only inside each candidate's
`harnessDir`, and keep the `runCommand` concrete enough for `/fuzz --stage replay` to execute. Do not edit
application source from this command.
